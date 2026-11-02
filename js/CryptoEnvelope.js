/* Versioned message format shared by text and PNG exports. */
class CryptoEnvelope {
  static MAGIC = new Uint8Array([74,67,83,50]); // JCS2
  static ITERATIONS = 250000;
  static async key(password,salt) {
    if (!globalThis.crypto?.subtle) throw new Error('Encryption requires HTTPS or localhost and a browser with Web Crypto.');
    if (!password) throw new Error('Enter a password.');
    const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:this.ITERATIONS},material,{name:'AES-GCM',length:128},false,['encrypt','decrypt']);
  }
  static isCurrent(bytes) { return bytes.length>=4 && this.MAGIC.every((v,i)=>bytes[i]===v); }
  static async encrypt(message,password) {
    if(!message)throw new Error('Enter a message to encrypt.');
    if(!globalThis.crypto?.subtle)throw new Error('Open this app over HTTPS or localhost to encrypt.');
    const plain=new TextEncoder().encode(message);
    if(plain.length>1048576)throw new Error('Keep the message below 1 MiB.');
    const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
    const header=CryptoTextEncoder.concatBytes(this.MAGIC,salt,iv);
    const key=await this.key(password,salt);
    const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:header,tagLength:128},key,plain);
    return CryptoTextEncoder.concatBytes(header,new Uint8Array(ciphertext));
  }
  static async decrypt(bytes,password) {
    if(!password)throw new Error('Enter the password used for encryption.');
    if(!this.isCurrent(bytes))return this.decryptLegacy(bytes,password);
    if(bytes.length<49)throw new Error('The encrypted message is incomplete.');
    const salt=bytes.slice(4,20),iv=bytes.slice(20,32);
    const key=await this.key(password,salt);
    try {
      const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:bytes.slice(0,32),tagLength:128},key,bytes.slice(32));
      return {text:new TextDecoder('utf-8',{fatal:true}).decode(plain),legacy:false};
    } catch {throw new Error('Incorrect password or damaged encrypted message.');}
  }
  static toText(bytes) { return (this.isCurrent(bytes)?'JC2.':'JC1.')+CryptoTextEncoder.bytesToBase64(bytes); }
  static fromText(text) {
    text=text.trim().replace(/\s/g,'');
    if(!/^JC[12]\./.test(text))throw new Error('Paste a complete JC2 message. Older bare Base64 text is not supported here.');
    const bytes=CryptoTextEncoder.base64ToBytes(text.slice(4));
    if(text.startsWith('JC2.')&&!this.isCurrent(bytes))throw new Error('Invalid message header.');
    if(text.startsWith('JC1.')&&(bytes[0]!==1||![0,1].includes(bytes[1])))throw new Error('Invalid legacy message header.');
    return bytes;
  }
  // Compatibility with version-1 images produced by the supplied app.
  static async decryptLegacy(bytes,password) {
    if(bytes.length<3||bytes[0]!==1||![0,1].includes(bytes[1]))throw new Error('This is not a supported encrypted message.');
    let key,cipher;
    if(bytes[1]===0){key=KeyDeriver.deriveXOR(password);cipher=bytes.slice(2);}
    else {
      const length=bytes[2];
      if(length<1||3+length>=bytes.length)throw new Error('Invalid legacy salt.');
      key=(await KeyDeriver.derive(password,'pbkdf2',{salt:bytes.slice(3,3+length)})).key;
      cipher=bytes.slice(3+length);
    }
    if(!cipher.length||cipher.length%16)throw new Error('Invalid legacy AES data.');
    try {
      const aes=new AES128(key),blocks=CryptoTextEncoder.splitIntoBlocks(cipher).map(block=>aes.decryptBlock(block));
      return {text:CryptoTextEncoder.decode(CryptoTextEncoder.removePKCS7Padding(CryptoTextEncoder.joinBlocks(blocks))),legacy:true};
    }catch {throw new Error('Incorrect password or damaged legacy message.');}
  }
}
