import {generateKeyPairSync} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
try { process.loadEnvFile(); } catch (e) { if (e.code !== 'ENOENT') throw e; }
const dir=process.env.KEY_DIR||'./keys', id=process.env.KEY_ID||'v1';
mkdirSync(dir,{recursive:true,mode:0o700});
for(const [name,type,options] of [['sign','ed25519',{}],['encrypt','rsa',{modulusLength:3072}]]){
 const {privateKey,publicKey}=generateKeyPairSync(type,{...options,privateKeyEncoding:{type:'pkcs8',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}});
 for(const [suffix,value] of [['private',privateKey],['public',publicKey]])writeFileSync(`${dir}/${id}-${name}-${suffix}.pem`,value,{flag:'wx',mode:0o600});
}
