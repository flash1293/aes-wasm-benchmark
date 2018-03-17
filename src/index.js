import aesWasm from 'tiny-aes-wasm/256';
import aesJs from "aes-js";

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
    plainBuffer = buf;
  }
}

const root = document.getElementById('root');
root.innerHTML = '<h1>tiny-aem-wasm Benchmark</h1><button id="start">Run Benchmark</button><table id="results"><tr><th>label</th><th>mean time (ms/run)</th></tr></table>';

let plainBuffer;
const ivBuffer = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff];
const keyBuffer = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4];

document.getElementById('start').addEventListener('click', () => {
  aesWasm().then((aesWasmInstance) => {
    const aesJsInstance = new aesJs.ModeOfOperation.ctr(keyBuffer, new aesJs.Counter(ivBuffer));
    aesWasmInstance.init(keyBuffer, ivBuffer, 'CTR');

    benchmark('aes-js 8MB', fillPlainBuffer(2**23), () => {
      aesJsInstance.encrypt(plainBuffer);
    }, 1);
    benchmark('tiny-aes-wasm 8MB', fillPlainBuffer(2**23), () => {
      aesWasmInstance.encrypt(plainBuffer);
    }, 1);
    benchmark('aes-js 1MB', fillPlainBuffer(2**20), () => {
      aesJsInstance.encrypt(plainBuffer);
    }, 10);
    benchmark('tiny-aes-wasm 1MB', fillPlainBuffer(2**20), () => {
      aesWasmInstance.encrypt(plainBuffer);
    }, 10);
    benchmark('aes-js 1KB', fillPlainBuffer(2**10), () => {
      aesJsInstance.encrypt(plainBuffer);
    }, 10000);
    benchmark('tiny-aes-wasm 1KB', fillPlainBuffer(2**10), () => {
      aesWasmInstance.encrypt(plainBuffer);
    }, 10000);
    benchmark('aes-js 64 byte', fillPlainBuffer(2**6), () => {
      aesJsInstance.encrypt(plainBuffer);
    }, 100000);
    benchmark('tiny-aes-wasm 64 byte', fillPlainBuffer(2**6), () => {
      aesWasmInstance.encrypt(plainBuffer);
    }, 10000);
  });
});


// This is needed for Hot Module Replacement
if (module.hot) {
  module.hot.accept();
}
