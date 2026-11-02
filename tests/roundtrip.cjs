const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),assert=require('node:assert/strict');
const {webcrypto}=require('node:crypto');
class ImageData {constructor(data,width,height){this.data=data;this.width=width;this.height=height;}}
const context={console,crypto:webcrypto,TextEncoder,TextDecoder,Uint8Array,Uint8ClampedArray,ArrayBuffer,DataView,ImageData,btoa:s=>Buffer.from(s,'binary').toString('base64'),atob:s=>Buffer.from(s,'base64').toString('binary')};context.window=context;vm.createContext(context);
for(const name of ['AESUtils','AES128','KeyDeriver','TextEncoder','LSBSteganography','CryptoEnvelope'])vm.runInContext(fs.readFileSync(path.resolve(__dirname,'../js/'+name+'.js'),'utf8'),context);
vm.runInContext('globalThis.envelope=CryptoEnvelope;globalThis.stego=LSBSteganography;',context);
(async()=>{
 const {envelope:E,stego:S}=context,message='Meet by the bridge. π 🌳\nSecond line.',password='correct horse copper compass';
 const first=await E.encrypt(message,password),second=await E.encrypt(message,password);assert.notDeepEqual(first,second);
 assert.equal((await E.decrypt(E.fromText(E.toText(first)),password)).text,message);
 await assert.rejects(()=>E.decrypt(first,'incorrect'),/Incorrect password/);
 const altered=first.slice();altered[altered.length-1]^=1;await assert.rejects(()=>E.decrypt(altered,password),/damaged/);
 const carrier=new ImageData(new Uint8ClampedArray(160*100*4).fill(255),160,100),original=carrier.data.slice();
 const hidden=S.hideData(carrier,first);assert.deepEqual(carrier.data,original);const extracted=S.extractData(hidden);assert.deepEqual(Array.from(extracted),Array.from(first));assert.equal((await E.decrypt(extracted,password)).text,message);
 for(let i=0;i<hidden.data.length;i++){assert.ok(Math.abs(hidden.data[i]-carrier.data[i])<=1);if(i%4===3)assert.equal(hidden.data[i],255);}
 assert.throws(()=>S.hideData(new ImageData(new Uint8ClampedArray(16).fill(255),2,2),first),/large/);
 assert.equal(S.containsPayload(carrier),false);await assert.rejects(()=>E.encrypt('',password),/Enter a message/);
 if(process.env.CRYPTO_FIXTURE)fs.writeFileSync(process.env.CRYPTO_FIXTURE,hidden.data);
 console.log('PASS: Unicode text + LSB round trips, random salt/IV, wrong-password rejection, tamper rejection, carrier immutability, alpha retention, capacity and empty input.');
})().catch(e=>{console.error(e);process.exit(1)});
