import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { randomBytes, randomUUID } from "node:crypto";
import { z, ZodError } from "zod";
import QRCode from "qrcode";
import JSZip from "jszip";
import * as D from "./db.js";
import { permissions } from "./permissions.js";
import { seal, unseal, digest, keyId } from "./crypto.js";
const {
  User,
  Role,
  Manufacturer,
  Batch,
  QR,
  Token,
  Approval,
  PrintLog,
  Scan,
  Violation,
  Audit,
  Setting,
  Notification,
} = D;
for (const k of ["JWT_SECRET", "TOKEN_PEPPER"])
  if (
    (process.env[k] || "").length < 64 ||
    process.env[k].startsWith("replace-")
  )
    throw Error(`${k} must be a random secret of at least 64 characters`);
const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(
  cors({
    origin: (o, cb) =>
      cb(null, !o || (process.env.CORS_ORIGINS || "").split(",").includes(o)),
    credentials: false,
  }),
);
app.use(express.json({ limit: "64kb" }));
app.use(rateLimit({ windowMs: 60000, limit: 180 }));
const api = express.Router();
app.use("/api/v1", api);
const fail = (status, message) => {
  throw Object.assign(Error(message), { status });
};
const str = z.string().trim().min(1).max(500),
  id = z.string().regex(/^[a-fA-F0-9]{24}$/),
  email = z
    .string()
    .email()
    .max(254)
    .transform((x) => x.toLowerCase()),
  password = z
    .string()
    .min(12)
    .max(72)
    .refine((x) => Buffer.byteLength(x) <= 72),
  remarks = z.string().trim().max(2000),
  code = z.string().regex(/^\d{6}$/);
const parse = (schema, req) => schema.strict().parse(req.body);
const getId = (req) => id.parse(req.params.id);
const found = async (p) => {
  const v = await p;
  if (!v) fail(404, "Not found");
  return v;
};
const ref = (x) => String(x?._id || x);
const own = (req, m) => {
  if (!req.user.manufacturer || ref(req.user.manufacturer) !== ref(m))
    fail(403, "Forbidden");
};
const has = (req, p) => req.user.role.permissions.includes(p);
const permit =
  (...ps) =>
  (req, res, next) => {
    if (!ps.some((p) => has(req, p))) fail(403, "Forbidden");
    next();
  };
const audit = async (req, action, entity, entityId, session, details) => {
  try {
    await Audit.create({
      actor: req.user?._id,
      action,
      entity,
      entityId: String(entityId),
      ip: req.ip,
      details,
    });
  } catch (e) {
    console.error("AUDIT WRITE FAILED", action, String(entityId), e.message);
  }
};
const authLimit = rateLimit({ windowMs: 15 * 60000, limit: 20 });
const access = (u, family) =>
  jwt.sign({ sub: ref(u), family, kind: "access" }, process.env.JWT_SECRET, {
    algorithm: "HS256",
    issuer: "bpvs",
    audience: "bpvs-api",
    expiresIn: "10m",
  });
const random = () => randomBytes(48).toString("base64url");
async function issue(u, family = randomUUID()) {
  const refreshToken = random();
  await Token.create([
    {
      user: u._id,
      digest: digest(refreshToken),
      family,
      expiresAt: new Date(Date.now() + 7 * 86400000),
    },
  ]);
  return { accessToken: access(u, family), refreshToken, expiresIn: 600 };
}
async function auth(req, res, next) {
  let p;
  try {
    p = jwt.verify(
      (req.headers.authorization || "").replace(/^Bearer /, ""),
      process.env.JWT_SECRET,
      { algorithms: ["HS256"], issuer: "bpvs", audience: "bpvs-api" },
    );
  } catch {
    fail(401, "Invalid access token");
  }
  if (p.kind !== "access") fail(401, "Invalid token type");
  const u = await User.findById(p.sub).populate("role");
  if (
    !u?.active ||
    !u.role ||
    !(await Token.exists({
      user: u._id,
      family: p.family,
      revoked: false,
      used: false,
      expiresAt: { $gt: new Date() },
    }))
  )
    fail(401, "Session revoked");
  if (
    u.manufacturer &&
    !(await Manufacturer.exists({ _id: u.manufacturer, status: "APPROVED" }))
  )
    fail(403, "Manufacturer not approved");
  req.user = u;
  req.family = p.family;
  next();
}
api.get("/health", (req, res) =>
  res.json({
    status: mongoose.connection.readyState === 1 ? "ok" : "unavailable",
  }),
);
api.post("/auth/register", authLimit, async (req, res) => {
  const b = parse(
    z.object({
      name: str,
      email,
      password,
      companyName: str,
      address: str,
      license: str,
    }),
    req,
  );
  const role = await found(Role.findOne({ name: "MANUFACTURER" }));
  if (await User.exists({ email: b.email }))
    fail(409, "Email already registered");
  const passwordHash = await bcrypt.hash(b.password, 12);
  const m = await Manufacturer.create({
    name: b.companyName,
    companyId: `MFG-${randomUUID()}`,
    address: b.address,
    license: b.license,
  });
  try {
    await User.create({
      name: b.name,
      email: b.email,
      passwordHash,
      role: role._id,
      manufacturer: m._id,
    });
  } catch (e) {
    if (!(await User.exists({ manufacturer: m._id })))
      await Manufacturer.deleteOne({ _id: m._id, status: "PENDING" });
    throw e;
  }
  await audit(req, "REGISTER", "manufacturer", m._id);
  res.status(201).json({ status: "PENDING" });
});
api.post("/auth/login", authLimit, async (req, res) => {
  const b = parse(
    z.object({ email, password: z.string().min(1).max(72) }),
    req,
  );
  const u = await User.findOne({ email: b.email })
    .select("+passwordHash")
    .populate("role");
  if (
    !u?.active ||
    !u.role ||
    !(await bcrypt.compare(b.password, u.passwordHash))
  )
    fail(401, "Invalid credentials");
  if (
    u.manufacturer &&
    !(await Manufacturer.exists({ _id: u.manufacturer, status: "APPROVED" }))
  )
    fail(403, "Manufacturer not approved");
  res.json(await issue(u));
});
api.post("/auth/refresh", authLimit, async (req, res) => {
  const { refreshToken } = parse(z.object({ refreshToken: str }), req);
  const t = await Token.findOne({ digest: digest(refreshToken) });
  if (!t || t.revoked || t.expiresAt <= new Date())
    fail(401, "Invalid refresh token");
  if (t.used) {
    await Token.updateMany({ family: t.family }, { $set: { revoked: true } });
    fail(401, "Refresh reuse detected");
  }
  const u = await User.findById(t.user);
  if (
    !u?.active ||
    (u.manufacturer &&
      !(await Manufacturer.exists({ _id: u.manufacturer, status: "APPROVED" })))
  )
    fail(401, "Account unavailable");
  const result = await (async (s) => {
    const claimed = await Token.findOneAndUpdate(
      { _id: t._id, used: false, revoked: false },
      { $set: { used: true } },
      {},
    );
    if (!claimed) return null;
    return issue(u, t.family);
  })();
  if (!result) {
    await Token.updateMany({ family: t.family }, { $set: { revoked: true } });
    fail(401, "Refresh reuse detected");
  }
  res.json(result);
});
api.use(auth);
api.post("/auth/logout", async (req, res) => {
  await Token.updateMany({ family: req.family }, { $set: { revoked: true } });
  res.sendStatus(204);
});
api.get("/auth/me", (req, res) => res.json(req.user));
function list(path, model, perms, filter = () => ({}), populate = []) {
  api.get(path, permit(...perms), async (req, res) => {
    const page = z.coerce
      .number()
      .int()
      .min(1)
      .max(100000)
      .parse(req.query.page ?? 1);

    const limit = z.coerce
      .number()
      .int()
      .min(1)
      .max(100)
      .parse(req.query.limit ?? 20);

    const q = filter(req);

    let query = model
      .find(q)
      .sort({ createdAt: -1, _id: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    // Populate references only when configured
    if (populate.length > 0) {
      query = query.populate(populate);
    }

    const [items, total] = await Promise.all([
      query.lean(),
      model.countDocuments(q),
    ]);

    res.json({
      items,
      total,
      page,
      limit,
    });
  });
}
list("/roles", Role, ["roles.manage"]);
api.get("/permissions", permit("roles.manage"), (req, res) =>
  res.json(permissions),
);
api.post("/roles", permit("roles.manage"), async (req, res) => {
  const b = parse(
    z.object({
      name: str,
      permissions: z.array(z.enum(permissions)).max(permissions.length),
    }),
    req,
  );
  if (
    b.permissions.includes("roles.manage") ||
    b.permissions.includes("users.manage")
  )
    fail(403, "Privileged delegation prohibited");
  const r = await Role.create(b);
  await audit(req, "CREATE", "role", r._id);
  res.status(201).json(r);
});
api.patch("/roles/:id", permit("roles.manage"), async (req, res) => {
  const b = parse(z.object({ permissions: z.array(z.enum(permissions)) }), req);
  if (
    b.permissions.includes("roles.manage") ||
    b.permissions.includes("users.manage")
  )
    fail(403, "Privileged delegation prohibited");
  const r = await found(
    Role.findOneAndUpdate(
      { _id: getId(req), protected: false },
      { $set: b },
      { new: true },
    ),
  );
  await audit(req, "UPDATE", "role", r._id);
  res.json(r);
});
list("/users", User, ["users.manage"]);
api.post("/users", permit("users.manage"), async (req, res) => {
  const b = parse(z.object({ name: str, email, password, role: id }), req);
  const r = await found(Role.findById(b.role));
  if (["SUPER_ADMIN", "MANUFACTURER"].includes(r.name))
    fail(403, "Use designated provisioning flow");
  const u = await User.create({
    name: b.name,
    email: b.email,
    passwordHash: await bcrypt.hash(b.password, 12),
    role: r._id,
  });
  await audit(req, "CREATE", "user", u._id);
  res.status(201).json({ id: u._id, email: u.email });
});
api.patch("/users/:id/status", permit("users.manage"), async (req, res) => {
  const b = parse(z.object({ active: z.boolean() }), req);
  const u = await found(User.findById(getId(req)).populate("role"));
  if (u.role.name === "SUPER_ADMIN") fail(403, "Protected account");
  await (async (s) => {
    await User.updateOne({ _id: u._id }, { $set: b }, {});
    await Token.updateMany({ user: u._id }, { $set: { revoked: true } }, {});
    await audit(req, "STATUS", "user", u._id, s, b);
  })();
  res.sendStatus(204);
});
list("/manufacturers", Manufacturer, ["manufacturers.read"]);
api.get("/manufacturers/me", async (req, res) => {
  if (!req.user.manufacturer) fail(403, "Forbidden");
  res.json(await found(Manufacturer.findById(req.user.manufacturer)));
});
api.get("/manufacturers/:id", permit("manufacturers.read"), async (req, res) =>
  res.json(await found(Manufacturer.findById(getId(req)))),
);
api.post(
  "/manufacturers/:id/review",
  permit("manufacturers.review"),
  async (req, res) => {
    const b = parse(
      z.object({
        decision: z.enum(["APPROVED", "REJECTED", "SUSPENDED"]),
        remarks: remarks.min(1),
      }),
      req,
    );
    const m = await (async (s) => {
      const m = await found(
        Manufacturer.findOneAndUpdate(
          {
            _id: getId(req),
            status: {
              $in:
                b.decision === "SUSPENDED"
                  ? ["APPROVED"]
                  : ["PENDING", "SUSPENDED"],
            },
          },
          { $set: { status: b.decision, remarks: b.remarks } },
          { new: true },
        ),
      );
      await Approval.create(
        [
          {
            entityType: "manufacturer",
            entity: m._id,
            actor: req.user._id,
            ...b,
          },
        ],
        {},
      );
      await audit(req, "REVIEW", "manufacturer", m._id, s, b);
      return m;
    })();
    res.json(m);
  },
);
const batchSchema = z.object({
  bagSize: str,
  quantity: z.number().int().positive().max(100000000),
  startDate: z.string().datetime({ offset: true }),
  endDate: z.string().datetime({ offset: true }),
  distributionArea: str,
});
function dates(b) {
  if (new Date(b.endDate) < new Date(b.startDate))
    fail(400, "Invalid production dates");
}
const batchFilter = (req) =>
  has(req, "batches.read.all")
    ? {}
    : { manufacturer: req.user.manufacturer || null };
list(
  "/batches",
  Batch,
  ["batches.read.all", "batches.read.own"],
  batchFilter,
  [
    {
      path: "manufacturer",
      select: "name companyId",
    },
  ],
);
api.post("/batches", permit("batches.create"), async (req, res) => {
  const b = parse(batchSchema, req);
  dates(b);
  if (!req.user.manufacturer) fail(403, "Manufacturer required");
  const r = await Batch.create({
    ...b,
    batchId: `BATCH-${randomUUID()}`,
    manufacturer: req.user.manufacturer,
  });
  await audit(req, "CREATE", "batch", r._id);
  res.status(201).json(r);
});
api.get(
  "/batches/:id",
  permit("batches.read.all", "batches.read.own"),
  async (req, res) =>
    res.json(
      await found(Batch.findOne({ _id: getId(req), ...batchFilter(req) })),
    ),
);
api.patch("/batches/:id", permit("batches.edit.own"), async (req, res) => {
  const b = parse(batchSchema, req);
  dates(b);
  const r = await found(
    Batch.findOneAndUpdate(
      {
        _id: getId(req),
        manufacturer: req.user.manufacturer,
        status: "PENDING",
        reviewLocked: { $ne: true },
      },
      { $set: b },
      { new: true, runValidators: true },
    ),
  );
  await audit(req, "EDIT", "batch", r._id);
  res.json(r);
});
api.post("/batches/:id/review", permit("batches.review"), async (req, res) => {
  const b = parse(
    z.object({
      decision: z.enum(["APPROVED", "REJECTED"]),
      remarks: remarks.min(1),
    }),
    req,
  );
  const batch = await found(
    Batch.findOneAndUpdate(
      { _id: getId(req), status: "PENDING" },
      { $set: { reviewLocked: true } },
      { new: true },
    ),
  );
  if (batch.status !== "PENDING") fail(409, "Batch already reviewed");
  let qr;
  if (b.decision === "APPROVED") {
    const m = await found(
      Manufacturer.findOne({ _id: batch.manufacturer, status: "APPROVED" }),
    );
    const setting = await Setting.findOne({ name: "qr" });
    const now = new Date(),
      qrId = `QR-${randomUUID()}`,
      expiresAt = setting?.expiryDays
        ? new Date(+now + setting.expiryDays * 86400000)
        : null;
    const payload = seal({
      v: 1,
      qid: qrId,
      mid: m.companyId,
      bid: batch.batchId,
      qty: batch.quantity,
      iat: now.toISOString(),
      exp: expiresAt?.toISOString() || null,
    });
    await QRCode.toBuffer(payload, { errorCorrectionLevel: "M" });
    try {
      qr = await QR.findOneAndUpdate(
        { batch: batch._id },
        {
          $setOnInsert: {
            qrId,
            manufacturer: m._id,
            payload,
            keyId,
            expiresAt,
          },
        },
        { upsert: true, new: true },
      );
    } catch (e) {
      if (e.code !== 11000) throw e;
      qr = await found(QR.findOne({ batch: batch._id }));
    }
  }
  const updated = await Batch.findOneAndUpdate(
    { _id: batch._id, status: "PENDING", reviewLocked: true },
    { $set: { status: b.decision, remarks: b.remarks } },
    { new: true },
  );
  if (!updated) fail(409, "Batch changed; reload before reviewing");
  await Approval.create({
    entityType: "batch",
    entity: batch._id,
    actor: req.user._id,
    ...b,
  });
  const users = await User.find({ manufacturer: batch.manufacturer });
  if (users.length)
    await Notification.create(
      users.map((u) => ({
        user: u._id,
        title: "Batch decision",
        message: `${batch.batchId}: ${b.decision}`,
      })),
    );
  await audit(req, "REVIEW", "batch", batch._id, undefined, b);
  res.json({ batch: updated, qrId: qr?.qrId });
});


api.get(
  "/approvals",
  permit("batches.review", "manufacturers.review"),
  async (req, res) => {
    const page = z.coerce
      .number()
      .int()
      .min(1)
      .max(100000)
      .parse(req.query.page ?? 1);

    const limit = z.coerce
      .number()
      .int()
      .min(1)
      .max(100)
      .parse(req.query.limit ?? 20);

    const filter = {};

    const [approvals, total] = await Promise.all([
      Approval.find(filter)
        .populate("actor", "name email")
        .sort({ createdAt: -1, _id: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),

      Approval.countDocuments(filter),
    ]);

    // Separate references by entity type
    const batchIds = approvals
      .filter((item) => item.entityType === "batch")
      .map((item) => item.entity)
      .filter(Boolean);

    const manufacturerIds = approvals
      .filter((item) => item.entityType === "manufacturer")
      .map((item) => item.entity)
      .filter(Boolean);

    // Retrieve related records
    const [batches, manufacturers] = await Promise.all([
      Batch.find({
        _id: { $in: batchIds },
      })
        .select("batchId bagSize quantity manufacturer")
        .populate("manufacturer", "name companyId")
        .lean(),

      Manufacturer.find({
        _id: { $in: manufacturerIds },
      })
        .select("name companyId")
        .lean(),
    ]);

    // Create lookup maps
    const batchMap = new Map(
      batches.map((item) => [
        String(item._id),
        item,
      ]),
    );

    const manufacturerMap = new Map(
      manufacturers.map((item) => [
        String(item._id),
        item,
      ]),
    );

    // Prepare readable approval records
    const items = approvals.map((item) => {
      const entityId = String(item.entity);

      const record =
        item.entityType === "batch"
          ? batchMap.get(entityId)
          : item.entityType === "manufacturer"
            ? manufacturerMap.get(entityId)
            : null;

      return {
        ...item,

        record: record || null,

        recordName:
          item.entityType === "batch"
            ? record?.batchId || "Unknown batch"
            : item.entityType === "manufacturer"
              ? record?.name || "Unknown manufacturer"
              : "Unknown record",

        reviewedBy: item.actor?.name || "Unknown user",
      };
    });

    res.json({
      items,
      total,
      page,
      limit,
    });
  },
);

const qrFilter = (req) =>
  has(req, "qr.read.all")
    ? {}
    : { manufacturer: req.user.manufacturer || null };
api.get("/qr", permit("qr.read.all", "qr.read.own"), async (req, res) => {
  const page = z.coerce
      .number()
      .int()
      .min(1)
      .parse(req.query.page ?? 1),
    limit = z.coerce
      .number()
      .int()
      .min(1)
      .max(100)
      .parse(req.query.limit ?? 20);

  const ids = await Batch.find({
    status: "APPROVED",
  }).distinct("_id");

  const filter = {
    ...qrFilter(req),
    batch: { $in: ids },
  };

  const [items, total] = await Promise.all([
    QR.find(filter)
      .select("-payload")
      .populate({
        path: "batch",
        select: "batchId",
      })
      .sort({ createdAt: -1, _id: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),

    QR.countDocuments(filter),
  ]);

  res.json({
    items,
    total,
    page,
    limit,
  });
});
api.get(
  "/qr/:id/download",
  permit("qr.read.all", "qr.read.own"),
  async (req, res) => {
    const q = await found(QR.findOne({ _id: getId(req), ...qrFilter(req) }));
    if (
      !(await Batch.exists({ _id: q.batch, status: "APPROVED" })) ||
      !(await Manufacturer.exists({ _id: q.manufacturer, status: "APPROVED" }))
    )
      fail(409, "QR unavailable");
    if (q.revoked || (q.expiresAt && q.expiresAt <= new Date()))
      fail(409, "QR unavailable");
    const zip = new JSZip();
    zip.file(
      `${q.qrId}.png`,
      await QRCode.toBuffer(q.payload, { errorCorrectionLevel: "M", scale: 8 }),
    );
    await audit(req, "DOWNLOAD", "qr", q._id);
    res
      .attachment(`${q.qrId}.zip`)
      .send(await zip.generateAsync({ type: "nodebuffer" }));
  },
);
api.post("/qr/:id/revoke", permit("qr.revoke"), async (req, res) => {
  const b = parse(z.object({ remarks: remarks.min(1) }), req);
  await (async (s) => {
    const q = await found(
      QR.findByIdAndUpdate(getId(req), { $set: { revoked: true } }, {}),
    );
    await audit(req, "REVOKE", "qr", q._id, s, b);
  })();
  res.sendStatus(204);
});
api.post(
  "/production/:id/logs",
  permit("production.write.own"),
  async (req, res) => {
    const b = parse(
      z.object({
        units: z.number().int().positive().max(100000000),
        eventId: z.string().uuid(),
      }),
      req,
    );
    const batch = await found(
      Batch.findOne({
        _id: getId(req),
        manufacturer: req.user.manufacturer,
        status: "APPROVED",
      }),
    );
    let log;
    try {
      log = await PrintLog.findOneAndUpdate(
        { manufacturer: batch.manufacturer, eventId: b.eventId },
        { $setOnInsert: { ...b, batch: batch._id, actor: req.user._id } },
        { upsert: true, new: true },
      );
    } catch (e) {
      if (e.code !== 11000) throw e;
      log = await found(
        PrintLog.findOne({
          manufacturer: batch.manufacturer,
          eventId: b.eventId,
        }),
      );
    }
    if (ref(log.batch) !== ref(batch) || log.units !== b.units)
      fail(409, "Event ID already used");
    const totals = await PrintLog.aggregate([
      { $match: { batch: batch._id } },
      { $group: { _id: null, total: { $sum: "$units" } } },
    ]);
    const updated = await Batch.findByIdAndUpdate(
      batch._id,
      {
        $max: { reportedPrinted: totals[0]?.total || 0 },
        $set: { productionStatus: "IN_PRODUCTION" },
      },
      { new: true },
    );
    await audit(req, "PRINT_LOG", "batch", batch._id, undefined, b);
    res.status(201).json({
      reportedPrinted: updated.reportedPrinted,
      approved: updated.quantity,
      excess: Math.max(0, updated.reportedPrinted - updated.quantity),
      source: "SELF_REPORTED",
    });
  },
);
list(
  "/production/logs",
  PrintLog,
  ["production.read.all", "production.write.own"],
  (req) =>
    has(req, "production.read.all")
      ? {}
      : { manufacturer: req.user.manufacturer || null },
);
api.post("/scans", permit("scans.create"), async (req, res) => {
  const b = parse(
    z.object({
      payload: z.string().max(4096).min(1),
      latitude: z.number().min(-90).max(90).optional(),
      longitude: z.number().min(-180).max(180).optional(),
      clientEventId: z.string().uuid().optional(),
      observedAt: z.string().datetime({ offset: true }).optional(),
      offline: z.boolean().default(false),
    }),
    req,
  );
  let data,
    q,
    batch,
    m,
    result = "INVALID_QR";
  try {
    data = unseal(b.payload);
  } catch {}
  if (data) {
    q = await QR.findOne({ qrId: data.qid, payload: b.payload });
    if (q) {
      batch = await Batch.findById(q.batch);
      m = await Manufacturer.findById(q.manufacturer);
      result = q.revoked
        ? "REVOKED"
        : q.expiresAt && q.expiresAt <= new Date()
          ? "EXPIRED"
          : batch?.status !== "APPROVED" || m?.status !== "APPROVED"
            ? "UNAUTHORIZED"
            : "DIGITAL_VALID";
    }
  }
  const { payload, ...meta } = b;
  const scan = await Scan.create({
    ...meta,
    officer: req.user._id,
    qr: q?._id,
    batch: batch?._id,
    manufacturer: m?._id,
    result,
  });
  res.status(201).json({
    scanId: scan._id,
    result,
    physicalAntiClone: "NOT_VERIFIED",
    productionCompliance: "NOT_VERIFIED",
    materialCompliance: "NOT_VERIFIED",
    batch: batch
      ? {
          batchId: batch.batchId,
          quantity: batch.quantity,
          bagSize: batch.bagSize,
          distributionArea: batch.distributionArea,
        }
      : null,
    manufacturer: m ? { name: m.name, companyId: m.companyId } : null,
  });
});
list(
  "/scans",
  Scan,
  ["scans.read.all", "scans.read.own"],
  (req) =>
    has(req, "scans.read.all")
      ? {}
      : { officer: req.user._id },
  [
    {
      path: "officer",
      select: "name email",
    },
    {
      path: "batch",
      select: "batchId",
    },
  ],
);
api.post("/violations", permit("violations.create"), async (req, res) => {
  const b = parse(
    z.object({
      scan: id,
      type: z.enum(["FAKE_QR", "SUSPECTED_DUPLICATE", "OTHER"]),
      remarks: remarks.min(1),
    }),
    req,
  );
  const scan = await found(
    Scan.findOne({ _id: b.scan, officer: req.user._id }),
  );
  const v = await Violation.create({
    ...b,
    officer: req.user._id,
    batch: scan.batch,
  });
  await audit(req, "REPORT", "violation", v._id);
  res.status(201).json(v);
});
list(
  "/violations",
  Violation,
  ["violations.read.all", "violations.read.own"],
  (req) => (has(req, "violations.read.all") ? {} : { officer: req.user._id }),
);
api.patch(
  "/violations/:id/review",
  permit("violations.review"),
  async (req, res) => {
    const b = parse(z.object({ reviewRemarks: remarks.min(1) }), req);
    const v = await found(
      Violation.findByIdAndUpdate(
        getId(req),
        { $set: { ...b, status: "REVIEWED" } },
        { new: true },
      ),
    );
    await audit(req, "REVIEW", "violation", v._id);
    res.json(v);
  },
);
api.get("/settings/qr", permit("settings.manage"), async (req, res) =>
  res.json((await Setting.findOne({ name: "qr" })) || { expiryDays: null }),
);
api.put("/settings/qr", permit("settings.manage"), async (req, res) => {
  const b = parse(
    z.object({ expiryDays: z.number().int().min(1).max(3650).nullable() }),
    req,
  );
  const r = await (async (s) => {
    const r = await Setting.findOneAndUpdate(
      { name: "qr" },
      { $set: b },
      { upsert: true, new: true },
    );
    await audit(req, "CONFIGURE", "settings", r._id, s, b);
    return r;
  })();
  res.json(r);
});
list("/audit", Audit, ["audit.read"]);
api.get("/notifications", async (req, res) =>
  res.json(
    await Notification.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(100),
  ),
);
api.patch("/notifications/:id/read", async (req, res) => {
  await found(
    Notification.findOneAndUpdate(
      { _id: getId(req), user: req.user._id },
      { $set: { read: true } },
    ),
  );
  res.sendStatus(204);
});
api.get(
  "/dashboard",
  permit("reports.read", "batches.read.own", "scans.read.own"),
  async (req, res) => {
    if (has(req, "reports.read")) {
      const [manufacturers, batches, scans, violations] = await Promise.all([
        Manufacturer.countDocuments(),
        Batch.aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }]),
        Scan.aggregate([{ $group: { _id: "$result", count: { $sum: 1 } } }]),
        Violation.countDocuments(),
      ]);
      return res.json({ manufacturers, batches, scans, violations });
    }
    if (req.user.manufacturer)
      return res.json({
        batches: await Batch.countDocuments({
          manufacturer: req.user.manufacturer,
        }),
      });
    res.json({
      scans: await Scan.countDocuments({ officer: req.user._id }),
      violations: await Violation.countDocuments({ officer: req.user._id }),
    });
  },
);
for (const [name, model] of Object.entries({
  manufacturers: Manufacturer,
  batches: Batch,
  approvals: Approval,
  qr: QR,
  scans: Scan,
  violations: Violation,
  activity: Audit,
}))
  list(`/reports/${name}`, model, ["reports.read"]);
app.use((req, res) => res.status(404).json({ message: "Route not found" }));
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status =
    err instanceof ZodError
      ? 400
      : err.code === 11000
        ? 409
        : err.status || 500;
  if (status === 500) console.error(err.name, err.message);
  res.status(status).json({
    message:
      status === 500
        ? "Internal server error"
        : err instanceof ZodError
          ? "Validation failed"
          : err.code === 11000
            ? "Duplicate record"
            : err.message,
    ...(err instanceof ZodError ? { issues: err.issues } : {}),
  });
});
await D.connect();
const server = app.listen(Number(process.env.PORT || 8080), () =>
  console.log("BPVS API listening"),
);
for (const sig of ["SIGTERM", "SIGINT"])
  process.on(sig, () =>
    server.close(async () => {
      await mongoose.disconnect();
      process.exit(0);
    }),
  );
