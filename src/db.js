import "dotenv/config";
import mongoose from "mongoose";

export async function connect() {
  if (!process.env.MONGO_URI) {
    throw Error("MONGO_URI required");
  }

  await mongoose.connect(process.env.MONGO_URI);

  await Promise.all(Object.values(mongoose.models).map((m) => m.init()));
}

const S = mongoose.Schema;
const O = S.Types.ObjectId;

const model = (name, fields, indexes = []) => {
  const s = new S(fields, {
    timestamps: true,
    strict: "throw",
  });

  for (const [keys, opts] of indexes) {
    s.index(keys, opts);
  }

  return mongoose.model(name, s);
};

// ==========================================
// ROLE
// ==========================================

export const Role = model("Role", {
  name: {
    type: String,
    unique: true,
    required: true,
  },

  permissions: [String],

  protected: {
    type: Boolean,
    default: false,
  },
});

// ==========================================
// MANUFACTURER
// ==========================================

export const Manufacturer = model("Manufacturer", {
  name: {
    type: String,
    required: true,
  },

  companyId: {
    type: String,
    unique: true,
    required: true,
  },

  address: String,
  license: String,

  status: {
    type: String,
    enum: ["PENDING", "APPROVED", "REJECTED", "SUSPENDED"],
    default: "PENDING",
  },

  remarks: String,
});

// ==========================================
// USER
// ==========================================

export const User = model("User", {
  email: {
    type: String,
    unique: true,
    required: true,
  },

  name: String,

  passwordHash: {
    type: String,
    select: false,
  },

  role: {
    type: O,
    ref: "Role",
    required: true,
  },

  manufacturer: {
    type: O,
    ref: "Manufacturer",
  },

  active: {
    type: Boolean,
    default: true,
  },

  totpSecret: {
    type: String,
    select: false,
  },

  totpPending: {
    type: String,
    select: false,
  },

  lastTotpStep: {
    type: Number,
    default: -1,
  },
});

// ==========================================
// TOKEN
// ==========================================

export const Token = model(
  "Token",
  {
    user: {
      type: O,
      ref: "User",
      required: true,
    },

    digest: {
      type: String,
      unique: true,
    },

    family: String,
    expiresAt: Date,

    used: {
      type: Boolean,
      default: false,
    },

    revoked: {
      type: Boolean,
      default: false,
    },
  },
  [[{ expiresAt: 1 }, { expireAfterSeconds: 0 }]],
);

// ==========================================
// BATCH
// ==========================================

export const Batch = model("Batch", {
  batchId: {
    type: String,
    unique: true,
  },

  manufacturer: {
    type: O,
    ref: "Manufacturer",
    required: true,
  },

  bagSize: String,
  quantity: Number,
  startDate: Date,
  endDate: Date,
  distributionArea: String,

  status: {
    type: String,
    enum: ["PENDING", "APPROVED", "REJECTED"],
    default: "PENDING",
  },

  productionStatus: {
    type: String,
    enum: ["NOT_STARTED", "IN_PRODUCTION", "SUPPLIED"],
    default: "NOT_STARTED",
  },

  reportedPrinted: {
    type: Number,
    default: 0,
  },

  remarks: String,

  reviewLocked: {
    type: Boolean,
    default: false,
  },
});

// ==========================================
// QR CODE
// ==========================================

export const QR = model("QR", {
  qrId: {
    type: String,
    unique: true,
  },

  batch: {
    type: O,
    ref: "Batch",
    unique: true,
    required: true,
  },

  manufacturer: {
    type: O,
    ref: "Manufacturer",
    required: true,
  },

  payload: String,
  keyId: String,
  expiresAt: Date,

  revoked: {
    type: Boolean,
    default: false,
  },
});

// ==========================================
// APPROVAL
// ==========================================

export const Approval = model("Approval", {
  entityType: String,

  entity: {
    type: O,
    refPath: "entityModel",
  },

  entityModel: {
    type: String,
    enum: ["Manufacturer", "Batch"],
  },

  actor: {
    type: O,
    ref: "User",
  },

  decision: String,
  remarks: String,
});

// ==========================================
// PRODUCTION LOG
// ==========================================

export const PrintLog = model(
  "PrintLog",
  {
    batch: {
      type: O,
      ref: "Batch",
    },

    manufacturer: {
      type: O,
      ref: "Manufacturer",
    },

    actor: {
      type: O,
      ref: "User",
    },

    units: Number,
    eventId: String,

    source: {
      type: String,
      default: "SELF_REPORTED",
    },
  },
  [[{ manufacturer: 1, eventId: 1 }, { unique: true }]],
);

// ==========================================
// FIELD SCAN
// ==========================================

export const Scan = model(
  "Scan",
  {
    officer: {
      type: O,
      ref: "User",
    },

    qr: {
      type: O,
      ref: "QR",
    },

    batch: {
      type: O,
      ref: "Batch",
    },

    manufacturer: {
      type: O,
      ref: "Manufacturer",
    },

    result: String,
    latitude: Number,
    longitude: Number,
    clientEventId: String,
    observedAt: Date,

    offline: {
      type: Boolean,
      default: false,
    },
  },
  [
    [
      { officer: 1, clientEventId: 1 },
      {
        unique: true,

        partialFilterExpression: {
          clientEventId: {
            $type: "string",
          },
        },
      },
    ],
  ],
);

// ==========================================
// VIOLATION
// ==========================================

export const Violation = model("Violation", {
  officer: {
    type: O,
    ref: "User",
  },

  scan: {
    type: O,
    ref: "Scan",
  },

  batch: {
    type: O,
    ref: "Batch",
  },

  type: {
    type: String,
    enum: ["FAKE_QR", "SUSPECTED_DUPLICATE", "OTHER"],
  },

  remarks: String,

  status: {
    type: String,
    enum: ["REPORTED", "REVIEWED"],
    default: "REPORTED",
  },

  reviewRemarks: String,
});

// ==========================================
// AUDIT LOG
// ==========================================

export const Audit = model("Audit", {
  actor: {
    type: O,
    ref: "User",
  },

  action: String,
  entity: String,
  entityId: String,
  ip: String,
  details: S.Types.Mixed,
});

// ==========================================
// SYSTEM SETTINGS
// ==========================================

export const Setting = model("Setting", {
  name: {
    type: String,
    unique: true,
  },

  expiryDays: {
    type: Number,
    default: null,
  },
});

// ==========================================
// NOTIFICATION
// ==========================================

export const Notification = model("Notification", {
  user: {
    type: O,
    ref: "User",
  },

  title: String,
  message: String,

  read: {
    type: Boolean,
    default: false,
  },
});
