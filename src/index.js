import { aes256 } from 'tiny-aes-wasm';
import sjcl from 'sjcl';

sjcl.codec.bytes = {
  /** Convert from a bitArray to an array of bytes. */
  fromBits: function (arr) {
    var out = [], bl = sjcl.bitArray.bitLength(arr), i, tmp;
    for (i=0; i<bl/8; i++) {
      if ((i&3) === 0) {
        tmp = arr[i/4];
      }
      out.push(tmp >>> 24);
      tmp <<= 8;
    }
    return out;
  },
  /** Convert from an array of bytes to a bitArray. */
  toBits: function (bytes) {
    var out = [], i, tmp=0;
    for (i=0; i<bytes.length; i++) {
      tmp = tmp << 8 | bytes[i];
      if ((i&3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i&3) {
      out.push(sjcl.bitArray.partial(8*(i&3), tmp));
    }
    return out;
  }
};

sjcl.mode.cbc = {
  /** The name of the mode.
   * @constant
   */
  name: "cbc",
  
  /** Encrypt in CBC mode with PKCS#5 padding.
   * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.  Must be empty.
   * @return The encrypted data, an array of bytes.
   * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits, or if any adata is specified.
   */
  encrypt: function(prp, plaintext, iv, adata) {
    if (adata && adata.length) {
      throw new sjcl.exception.invalid("cbc can't authenticate data");
    }
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("cbc iv must be 128 bits");
    }
    var i,
        w = sjcl.bitArray,
        xor = function(x,y) {
          return [x[0]^y[0],x[1]^y[1],x[2]^y[2],x[3]^y[3]];
        },
        bl = w.bitLength(plaintext),
        bp = 0,
        output = [];
    if (bl&7) {
      throw new sjcl.exception.invalid("pkcs#5 padding only works for multiples of a byte");
    }
  
    for (i=0; bp+128 <= bl; i+=4, bp+=128) {
      /* Encrypt a non-final block */
      iv = prp.encrypt(xor(iv, plaintext.slice(i,i+4)));
      output.splice(i,0,iv[0],iv[1],iv[2],iv[3]);
    }
    
    /* Construct the pad. */
    bl = (16 - ((bl >> 3) & 15)) * 0x1010101;
    /* Pad and encrypt. */
    iv = prp.encrypt(xor(iv,w.concat(plaintext,[bl,bl,bl,bl]).slice(i,i+4)));
    output.splice(i,0,iv[0],iv[1],iv[2],iv[3]);
    return output;
  },
  
  /** Decrypt in CBC mode.
   * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
   * @param {bitArray} ciphertext The ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.  It must be empty.
   * @return The decrypted data, an array of bytes.
   * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits, or if any adata is specified.
   * @throws {sjcl.exception.corrupt} if if the message is corrupt.
   */
  decrypt: function(prp, ciphertext, iv, adata) {
    if (adata && adata.length) {
      throw new sjcl.exception.invalid("cbc can't authenticate data");
    }
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("cbc iv must be 128 bits");
    }
    if ((sjcl.bitArray.bitLength(ciphertext) & 127) || !ciphertext.length) {
      throw new sjcl.exception.corrupt("cbc ciphertext must be a positive multiple of the block size");
    }
    var i,
        w = sjcl.bitArray,
        xor = w._xor4,
        bi, bo,
        output = [];
        
    adata = adata || [];
  
    for (i=0; i<ciphertext.length; i+=4) {
      bi = ciphertext.slice(i,i+4);
      bo = xor(iv,prp.decrypt(bi));
      output.splice(i,0,bo[0],bo[1],bo[2],bo[3]);
      iv = bi;
    }
    /* check and remove the pad */
    bi = output[i-1] & 255;
    if (bi === 0 || bi > 16) {
      throw new sjcl.exception.corrupt("pkcs#5 padding corrupt");
    }
    bo = bi * 0x1010101;
    if (!w.equal(w.bitSlice([bo,bo,bo,bo], 0, bi*8),
                 w.bitSlice(output, output.length*32 - bi*8, output.length*32))) {
      throw new sjcl.exception.corrupt("pkcs#5 padding corrupt");
    }
    return w.bitSlice(output, 0, output.length*32 - bi*8);
  }
};

function benchmark(label, prepareFn, testFn, reps = 1000) {
  const times=[];
  for(let i = 0; i < reps; i++) {
    prepareFn();
    const t0 = performance.now();
    testFn();
    const t1 = performance.now();
    times.push(t1 - t0);
  }
  const logEntry = document.createElement('tr');
  logEntry.innerHTML = `<td>${label}</td><td>${times.reduce((s, v) => s + v, 0) / times.length}</td>`;
  document.getElementById('results').appendChild(logEntry);
}

function fillPlainBuffer(size) {
  return () => {
    const buf = [];
    for (let i = 0; i < size; i++) {
      buf.push(Math.floor(Math.random() * 256));
    }
    plainBuffer = new Uint8Array(buf);
    plainBitArrayBuffer = sjcl.codec.bytes.toBits(plainBuffer);
  }
}

const root = document.getElementById('root');
root.innerHTML = '<h1>tiny-aem-wasm Benchmark</h1><button id="start">Run Benchmark</button><table id="results"><tr><th>label</th><th>mean time (ms/run)</th></tr></table>';

let plainBuffer;
let plainBitArrayBuffer;
const ivBuffer = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff];
const bitArrayIvBuffer = sjcl.codec.bytes.toBits(ivBuffer);
const keyBuffer = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4];
const wordKeyBuffer = [0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
                    0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4];

document.getElementById('start').addEventListener('click', () => {
  aes256().then((aesWasmInstance) => {
    const sjclInstance = new sjcl.cipher.aes(wordKeyBuffer);
    aesWasmInstance.init(keyBuffer, ivBuffer);

    benchmark('tiny-aes-wasm 4MB', fillPlainBuffer(2**22), () => {
      aesWasmInstance.encrypt(plainBuffer);
    }, 1);
    benchmark('sjcl 4MB', fillPlainBuffer(2**22), () => {
      sjcl.mode.cbc.encrypt(sjclInstance, plainBitArrayBuffer, bitArrayIvBuffer);
    }, 1);
    benchmark('tiny-aes-wasm 1MB', fillPlainBuffer(2**20), () => {
      aesWasmInstance.encrypt(plainBuffer);
    }, 10);
    benchmark('sjcl 1MB', fillPlainBuffer(2**20), () => {
      sjcl.mode.cbc.encrypt(sjclInstance, plainBitArrayBuffer, bitArrayIvBuffer);
    }, 10);
    benchmark('tiny-aes-wasm 1KB', fillPlainBuffer(2**10), () => {
      aesWasmInstance.encrypt(plainBuffer);
    }, 5000);
    benchmark('sjcl 1KB', fillPlainBuffer(2**10), () => {
      sjcl.mode.cbc.encrypt(sjclInstance, plainBitArrayBuffer, bitArrayIvBuffer);
    }, 5000);
    benchmark('tiny-aes-wasm 64 byte', fillPlainBuffer(2**6), () => {
      aesWasmInstance.encrypt(plainBuffer);
    }, 10000);
    benchmark('sjcl 64 byte', fillPlainBuffer(2**6), () => {
      sjcl.mode.cbc.encrypt(sjclInstance, plainBitArrayBuffer, bitArrayIvBuffer);
    }, 10000);
  });
});


// This is needed for Hot Module Replacement
if (module.hot) {
  module.hot.accept();
}
