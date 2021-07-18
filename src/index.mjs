import require$$0 from 'bip32';
import { Buffer as Buffer$1 } from 'buffer-es6';
import typef from 'typeforce';
import bip66 from 'bip66';
import ecc from 'tiny-secp256k1';
import pushdata from 'pushdata-bitcoin';
import require$$3 from 'bitcoin-ops';
import createHash from 'create-hash';
import bs58check from 'bs58check';
import bech32 from 'bech32';
import varuint$1 from 'varuint-bitcoin';
import require$$2 from '@asoltys/secp256k1-zkp';
import randomBytes$1 from 'randombytes';
import wif from 'wif';
import fastMerkleRoot from 'merkle-lib/fastRoot';
import require$$1 from 'bip174/src/lib/converter/varint';
import bip174_1 from 'bip174';
import utils_1 from 'bip174/src/lib/utils';

var commonjsGlobal = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

function createCommonjsModule(fn) {
  var module = { exports: {} };
	return fn(module, module.exports), module.exports;
}

var liquid = {
  messagePrefix: '\x18Liquid Signed Message:\n',
  bech32: 'ex',
  blech32: 'lq',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 57,
  scriptHash: 39,
  wif: 0x80,
  confidentialPrefix: 12,
  assetHash: '6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d',
};
var regtest = {
  messagePrefix: '\x18Liquid Signed Message:\n',
  bech32: 'ert',
  blech32: 'el',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 235,
  scriptHash: 75,
  wif: 0xef,
  confidentialPrefix: 4,
  assetHash: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
};

var networks$2 = /*#__PURE__*/Object.defineProperty({
	liquid: liquid,
	regtest: regtest
}, '__esModule', {value: true});

function decode$1(buffer, maxLength, minimal) {
  maxLength = maxLength || 4;
  minimal = minimal === undefined ? true : minimal;
  const length = buffer.length;
  if (length === 0) return 0;
  if (length > maxLength) throw new TypeError('Script number overflow');
  if (minimal) {
    if ((buffer[length - 1] & 0x7f) === 0) {
      if (length <= 1 || (buffer[length - 2] & 0x80) === 0)
        throw new Error('Non-minimally encoded script number');
    }
  }
  // 40-bit
  if (length === 5) {
    const a = buffer.readUInt32LE(0);
    const b = buffer.readUInt8(4);
    if (b & 0x80) return -((b & ~0x80) * 0x100000000 + a);
    return b * 0x100000000 + a;
  }
  // 32-bit / 24-bit / 16-bit / 8-bit
  let result = 0;
  for (let i = 0; i < length; ++i) {
    result |= buffer[i] << (8 * i);
  }
  if (buffer[length - 1] & 0x80)
    return -(result & ~(0x80 << (8 * (length - 1))));
  return result;
}
var decode_1$1 = decode$1;
function scriptNumSize(i) {
  return i > 0x7fffffff
    ? 5
    : i > 0x7fffff
    ? 4
    : i > 0x7fff
    ? 3
    : i > 0x7f
    ? 2
    : i > 0x00
    ? 1
    : 0;
}
function encode$1(_number) {
  let value = Math.abs(_number);
  const size = scriptNumSize(value);
  const buffer = Buffer$1.allocUnsafe(size);
  const negative = _number < 0;
  for (let i = 0; i < size; ++i) {
    buffer.writeUInt8(value & 0xff, i);
    value >>= 8;
  }
  if (buffer[size - 1] & 0x80) {
    buffer.writeUInt8(negative ? 0x80 : 0x00, size - 1);
  } else if (negative) {
    buffer[size - 1] |= 0x80;
  }
  return buffer;
}
var encode_1$1 = encode$1;

var script_number = /*#__PURE__*/Object.defineProperty({
	decode: decode_1$1,
	encode: encode_1$1
}, '__esModule', {value: true});

const UINT31_MAX = Math.pow(2, 31) - 1;
function UInt31(value) {
  return typef.UInt32(value) && value <= UINT31_MAX;
}
var UInt31_1 = UInt31;
function BIP32Path(value) {
  return typef.String(value) && !!value.match(/^(m\/)?(\d+'?\/)*\d+'?$/);
}
var BIP32Path_1 = BIP32Path;
BIP32Path.toJSON = () => {
  return 'BIP32 derivation path';
};
function Signer(obj) {
  return (
    (typef.Buffer(obj.publicKey) ||
      typeof obj.getPublicKey === 'function') &&
    typeof obj.sign === 'function'
  );
}
var Signer_1 = Signer;
const SATOSHI_MAX = 21 * 1e14;
function Satoshi(value) {
  return typef.UInt53(value) && value <= SATOSHI_MAX;
}
var Satoshi_1 = Satoshi;
// external dependent types
var ECPoint = typef.quacksLike('Point');
// exposed, external API
var Network = typef.compile({
  messagePrefix: typef.oneOf(typef.Buffer, typef.String),
  bip32: {
    public: typef.UInt32,
    private: typef.UInt32,
  },
  pubKeyHash: typef.UInt8,
  scriptHash: typef.UInt8,
  wif: typef.UInt8,
  assetHash: typef.String,
  confidentialPrefix: typef.UInt8,
});
var Buffer256bit = typef.BufferN(32);
var Hash160bit = typef.BufferN(20);
var Hash256bit = typef.BufferN(32);
var ConfidentialCommitment = typef.BufferN(33);
var ConfidentialValue = typef.BufferN(9);
var BufferOne = typef.BufferN(1);
var _Number = typef.Number; // tslint:disable-line variable-name
var _Array = typef.Array;
var _Boolean = typef.Boolean; // tslint:disable-line variable-name
var _String = typef.String; // tslint:disable-line variable-name
var Buffer = typef.Buffer;
var Hex = typef.Hex;
var _Object = typef.Object;
var maybe = typef.maybe;
var tuple = typef.tuple;
var UInt8 = typef.UInt8;
var UInt32 = typef.UInt32;
var _Function = typef.Function;
var BufferN = typef.BufferN;
var Null = typef.Null;
var oneOf = typef.oneOf;

var types$5 = /*#__PURE__*/Object.defineProperty({
	UInt31: UInt31_1,
	BIP32Path: BIP32Path_1,
	Signer: Signer_1,
	Satoshi: Satoshi_1,
	ECPoint: ECPoint,
	Network: Network,
	Buffer256bit: Buffer256bit,
	Hash160bit: Hash160bit,
	Hash256bit: Hash256bit,
	ConfidentialCommitment: ConfidentialCommitment,
	ConfidentialValue: ConfidentialValue,
	BufferOne: BufferOne,
	Number: _Number,
	Array: _Array,
	Boolean: _Boolean,
	String: _String,
	Buffer: Buffer,
	Hex: Hex,
	Object: _Object,
	maybe: maybe,
	tuple: tuple,
	UInt8: UInt8,
	UInt32: UInt32,
	Function: _Function,
	BufferN: BufferN,
	Null: Null,
	oneOf: oneOf
}, '__esModule', {value: true});

var __importStar$f =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };

const types$4 = __importStar$f(types$5);


const ZERO = Buffer$1.alloc(1, 0);
function toDER(x) {
  let i = 0;
  while (x[i] === 0) ++i;
  if (i === x.length) return ZERO;
  x = x.slice(i);
  if (x[0] & 0x80) return Buffer$1.concat([ZERO, x], 1 + x.length);
  return x;
}
function fromDER(x) {
  if (x[0] === 0x00) x = x.slice(1);
  const buffer = Buffer$1.alloc(32, 0);
  const bstart = Math.max(0, 32 - x.length);
  x.copy(buffer, bstart);
  return buffer;
}
// BIP62: 1 byte hashType flag (only 0x01, 0x02, 0x03, 0x81, 0x82 and 0x83 are allowed)
function decode(buffer) {
  const hashType = buffer.readUInt8(buffer.length - 1);
  const hashTypeMod = hashType & ~0x80;
  if (hashTypeMod <= 0 || hashTypeMod >= 4)
    throw new Error('Invalid hashType ' + hashType);
  const decoded = bip66.decode(buffer.slice(0, -1));
  const r = fromDER(decoded.r);
  const s = fromDER(decoded.s);
  const signature = Buffer$1.concat([r, s], 64);
  return { signature, hashType };
}
var decode_1 = decode;
function encode(signature, hashType) {
  typef(
    {
      signature: types$4.BufferN(64),
      hashType: types$4.UInt8,
    },
    { signature, hashType },
  );
  const hashTypeMod = hashType & ~0x80;
  if (hashTypeMod <= 0 || hashTypeMod >= 4)
    throw new Error('Invalid hashType ' + hashType);
  const hashTypeBuffer = Buffer$1.allocUnsafe(1);
  hashTypeBuffer.writeUInt8(hashType, 0);
  const r = toDER(signature.slice(0, 32));
  const s = toDER(signature.slice(32, 64));
  return Buffer$1.concat([bip66.encode(r, s), hashTypeBuffer]);
}
var encode_1 = encode;

var script_signature = /*#__PURE__*/Object.defineProperty({
	decode: decode_1,
	encode: encode_1
}, '__esModule', {value: true});

var OP_FALSE = 0;
var OP_0 = 0;
var OP_PUSHDATA1 = 76;
var OP_PUSHDATA2 = 77;
var OP_PUSHDATA4 = 78;
var OP_1NEGATE = 79;
var OP_RESERVED = 80;
var OP_TRUE = 81;
var OP_1 = 81;
var OP_2 = 82;
var OP_3 = 83;
var OP_4 = 84;
var OP_5 = 85;
var OP_6 = 86;
var OP_7 = 87;
var OP_8 = 88;
var OP_9 = 89;
var OP_10 = 90;
var OP_11 = 91;
var OP_12 = 92;
var OP_13 = 93;
var OP_14 = 94;
var OP_15 = 95;
var OP_16 = 96;
var OP_NOP = 97;
var OP_VER = 98;
var OP_IF = 99;
var OP_NOTIF = 100;
var OP_VERIF = 101;
var OP_VERNOTIF = 102;
var OP_ELSE = 103;
var OP_ENDIF = 104;
var OP_VERIFY = 105;
var OP_RETURN = 106;
var OP_TOALTSTACK = 107;
var OP_FROMALTSTACK = 108;
var OP_2DROP = 109;
var OP_2DUP = 110;
var OP_3DUP = 111;
var OP_2OVER = 112;
var OP_2ROT = 113;
var OP_2SWAP = 114;
var OP_IFDUP = 115;
var OP_DEPTH = 116;
var OP_DROP = 117;
var OP_DUP = 118;
var OP_NIP = 119;
var OP_OVER = 120;
var OP_PICK = 121;
var OP_ROLL = 122;
var OP_ROT = 123;
var OP_SWAP = 124;
var OP_TUCK = 125;
var OP_CAT = 126;
var OP_SUBSTR = 127;
var OP_LEFT = 128;
var OP_RIGHT = 129;
var OP_SIZE = 130;
var OP_INVERT = 131;
var OP_AND = 132;
var OP_OR = 133;
var OP_XOR = 134;
var OP_EQUAL = 135;
var OP_EQUALVERIFY = 136;
var OP_RESERVED1 = 137;
var OP_RESERVED2 = 138;
var OP_1ADD = 139;
var OP_1SUB = 140;
var OP_2MUL = 141;
var OP_2DIV = 142;
var OP_NEGATE = 143;
var OP_ABS = 144;
var OP_NOT = 145;
var OP_0NOTEQUAL = 146;
var OP_ADD = 147;
var OP_SUB = 148;
var OP_MUL = 149;
var OP_DIV = 150;
var OP_MOD = 151;
var OP_LSHIFT = 152;
var OP_RSHIFT = 153;
var OP_BOOLAND = 154;
var OP_BOOLOR = 155;
var OP_NUMEQUAL = 156;
var OP_NUMEQUALVERIFY = 157;
var OP_NUMNOTEQUAL = 158;
var OP_LESSTHAN = 159;
var OP_GREATERTHAN = 160;
var OP_LESSTHANOREQUAL = 161;
var OP_GREATERTHANOREQUAL = 162;
var OP_MIN = 163;
var OP_MAX = 164;
var OP_WITHIN = 165;
var OP_RIPEMD160 = 166;
var OP_SHA1 = 167;
var OP_SHA256 = 168;
var OP_HASH160 = 169;
var OP_HASH256 = 170;
var OP_CODESEPARATOR = 171;
var OP_CHECKSIG = 172;
var OP_CHECKSIGVERIFY = 173;
var OP_CHECKMULTISIG = 174;
var OP_CHECKMULTISIGVERIFY = 175;
var OP_NOP1 = 176;
var OP_NOP2 = 177;
var OP_CHECKLOCKTIMEVERIFY = 177;
var OP_NOP3 = 178;
var OP_CHECKSEQUENCEVERIFY = 178;
var OP_NOP4 = 179;
var OP_NOP5 = 180;
var OP_NOP6 = 181;
var OP_NOP7 = 182;
var OP_NOP8 = 183;
var OP_NOP9 = 184;
var OP_NOP10 = 185;
var OP_PUBKEYHASH = 253;
var OP_PUBKEY = 254;
var OP_INVALIDOPCODE = 255;
var OPS$7 = {
	OP_FALSE: OP_FALSE,
	OP_0: OP_0,
	OP_PUSHDATA1: OP_PUSHDATA1,
	OP_PUSHDATA2: OP_PUSHDATA2,
	OP_PUSHDATA4: OP_PUSHDATA4,
	OP_1NEGATE: OP_1NEGATE,
	OP_RESERVED: OP_RESERVED,
	OP_TRUE: OP_TRUE,
	OP_1: OP_1,
	OP_2: OP_2,
	OP_3: OP_3,
	OP_4: OP_4,
	OP_5: OP_5,
	OP_6: OP_6,
	OP_7: OP_7,
	OP_8: OP_8,
	OP_9: OP_9,
	OP_10: OP_10,
	OP_11: OP_11,
	OP_12: OP_12,
	OP_13: OP_13,
	OP_14: OP_14,
	OP_15: OP_15,
	OP_16: OP_16,
	OP_NOP: OP_NOP,
	OP_VER: OP_VER,
	OP_IF: OP_IF,
	OP_NOTIF: OP_NOTIF,
	OP_VERIF: OP_VERIF,
	OP_VERNOTIF: OP_VERNOTIF,
	OP_ELSE: OP_ELSE,
	OP_ENDIF: OP_ENDIF,
	OP_VERIFY: OP_VERIFY,
	OP_RETURN: OP_RETURN,
	OP_TOALTSTACK: OP_TOALTSTACK,
	OP_FROMALTSTACK: OP_FROMALTSTACK,
	OP_2DROP: OP_2DROP,
	OP_2DUP: OP_2DUP,
	OP_3DUP: OP_3DUP,
	OP_2OVER: OP_2OVER,
	OP_2ROT: OP_2ROT,
	OP_2SWAP: OP_2SWAP,
	OP_IFDUP: OP_IFDUP,
	OP_DEPTH: OP_DEPTH,
	OP_DROP: OP_DROP,
	OP_DUP: OP_DUP,
	OP_NIP: OP_NIP,
	OP_OVER: OP_OVER,
	OP_PICK: OP_PICK,
	OP_ROLL: OP_ROLL,
	OP_ROT: OP_ROT,
	OP_SWAP: OP_SWAP,
	OP_TUCK: OP_TUCK,
	OP_CAT: OP_CAT,
	OP_SUBSTR: OP_SUBSTR,
	OP_LEFT: OP_LEFT,
	OP_RIGHT: OP_RIGHT,
	OP_SIZE: OP_SIZE,
	OP_INVERT: OP_INVERT,
	OP_AND: OP_AND,
	OP_OR: OP_OR,
	OP_XOR: OP_XOR,
	OP_EQUAL: OP_EQUAL,
	OP_EQUALVERIFY: OP_EQUALVERIFY,
	OP_RESERVED1: OP_RESERVED1,
	OP_RESERVED2: OP_RESERVED2,
	OP_1ADD: OP_1ADD,
	OP_1SUB: OP_1SUB,
	OP_2MUL: OP_2MUL,
	OP_2DIV: OP_2DIV,
	OP_NEGATE: OP_NEGATE,
	OP_ABS: OP_ABS,
	OP_NOT: OP_NOT,
	OP_0NOTEQUAL: OP_0NOTEQUAL,
	OP_ADD: OP_ADD,
	OP_SUB: OP_SUB,
	OP_MUL: OP_MUL,
	OP_DIV: OP_DIV,
	OP_MOD: OP_MOD,
	OP_LSHIFT: OP_LSHIFT,
	OP_RSHIFT: OP_RSHIFT,
	OP_BOOLAND: OP_BOOLAND,
	OP_BOOLOR: OP_BOOLOR,
	OP_NUMEQUAL: OP_NUMEQUAL,
	OP_NUMEQUALVERIFY: OP_NUMEQUALVERIFY,
	OP_NUMNOTEQUAL: OP_NUMNOTEQUAL,
	OP_LESSTHAN: OP_LESSTHAN,
	OP_GREATERTHAN: OP_GREATERTHAN,
	OP_LESSTHANOREQUAL: OP_LESSTHANOREQUAL,
	OP_GREATERTHANOREQUAL: OP_GREATERTHANOREQUAL,
	OP_MIN: OP_MIN,
	OP_MAX: OP_MAX,
	OP_WITHIN: OP_WITHIN,
	OP_RIPEMD160: OP_RIPEMD160,
	OP_SHA1: OP_SHA1,
	OP_SHA256: OP_SHA256,
	OP_HASH160: OP_HASH160,
	OP_HASH256: OP_HASH256,
	OP_CODESEPARATOR: OP_CODESEPARATOR,
	OP_CHECKSIG: OP_CHECKSIG,
	OP_CHECKSIGVERIFY: OP_CHECKSIGVERIFY,
	OP_CHECKMULTISIG: OP_CHECKMULTISIG,
	OP_CHECKMULTISIGVERIFY: OP_CHECKMULTISIGVERIFY,
	OP_NOP1: OP_NOP1,
	OP_NOP2: OP_NOP2,
	OP_CHECKLOCKTIMEVERIFY: OP_CHECKLOCKTIMEVERIFY,
	OP_NOP3: OP_NOP3,
	OP_CHECKSEQUENCEVERIFY: OP_CHECKSEQUENCEVERIFY,
	OP_NOP4: OP_NOP4,
	OP_NOP5: OP_NOP5,
	OP_NOP6: OP_NOP6,
	OP_NOP7: OP_NOP7,
	OP_NOP8: OP_NOP8,
	OP_NOP9: OP_NOP9,
	OP_NOP10: OP_NOP10,
	OP_PUBKEYHASH: OP_PUBKEYHASH,
	OP_PUBKEY: OP_PUBKEY,
	OP_INVALIDOPCODE: OP_INVALIDOPCODE
};

var map = {};
for (var op in OPS$7) {
  var code = OPS$7[op];
  map[code] = op;
}

var map_1 = map;

var script$1 = createCommonjsModule(function (module, exports) {
var __importStar =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
const scriptNumber = __importStar(script_number);
const scriptSignature = __importStar(script_signature);
const types = __importStar(types$5);




exports.OPS = require$$3;

const OP_INT_BASE = exports.OPS.OP_RESERVED; // OP_1 - 1
function isOPInt(value) {
  return (
    types.Number(value) &&
    (value === exports.OPS.OP_0 ||
      (value >= exports.OPS.OP_1 && value <= exports.OPS.OP_16) ||
      value === exports.OPS.OP_1NEGATE)
  );
}
function isPushOnlyChunk(value) {
  return types.Buffer(value) || isOPInt(value);
}
function isPushOnly(value) {
  return types.Array(value) && value.every(isPushOnlyChunk);
}
exports.isPushOnly = isPushOnly;
function asMinimalOP(buffer) {
  if (buffer.length === 0) return exports.OPS.OP_0;
  if (buffer.length !== 1) return;
  if (buffer[0] >= 1 && buffer[0] <= 16) return OP_INT_BASE + buffer[0];
  if (buffer[0] === 0x81) return exports.OPS.OP_1NEGATE;
}
function chunksIsBuffer(buf) {
  return Buffer$1.isBuffer(buf);
}
function chunksIsArray(buf) {
  return types.Array(buf);
}
function singleChunkIsBuffer(buf) {
  return Buffer$1.isBuffer(buf);
}
function compile(chunks) {
  // TODO: remove me
  if (chunksIsBuffer(chunks)) return chunks;
  typef(types.Array, chunks);
  const bufferSize = chunks.reduce((accum, chunk) => {
    // data chunk
    if (singleChunkIsBuffer(chunk)) {
      // adhere to BIP62.3, minimal push policy
      if (chunk.length === 1 && asMinimalOP(chunk) !== undefined) {
        return accum + 1;
      }
      return accum + pushdata.encodingLength(chunk.length) + chunk.length;
    }
    // opcode
    return accum + 1;
  }, 0.0);
  const buffer = Buffer$1.allocUnsafe(bufferSize);
  let offset = 0;
  chunks.forEach(chunk => {
    // data chunk
    if (singleChunkIsBuffer(chunk)) {
      // adhere to BIP62.3, minimal push policy
      const opcode = asMinimalOP(chunk);
      if (opcode !== undefined) {
        buffer.writeUInt8(opcode, offset);
        offset += 1;
        return;
      }
      offset += pushdata.encode(buffer, chunk.length, offset);
      chunk.copy(buffer, offset);
      offset += chunk.length;
      // opcode
    } else {
      buffer.writeUInt8(chunk, offset);
      offset += 1;
    }
  });
  if (offset !== buffer.length) throw new Error('Could not decode chunks');
  return buffer;
}
exports.compile = compile;
function decompile(buffer) {
  // TODO: remove me
  if (chunksIsArray(buffer)) return buffer;
  typef(types.Buffer, buffer);
  const chunks = [];
  let i = 0;
  while (i < buffer.length) {
    const opcode = buffer[i];
    // data chunk
    if (opcode > exports.OPS.OP_0 && opcode <= exports.OPS.OP_PUSHDATA4) {
      const d = pushdata.decode(buffer, i);
      // did reading a pushDataInt fail?
      if (d === null) return null;
      i += d.size;
      // attempt to read too much data?
      if (i + d.number > buffer.length) return null;
      const data = buffer.slice(i, i + d.number);
      i += d.number;
      // decompile minimally
      const op = asMinimalOP(data);
      if (op !== undefined) {
        chunks.push(op);
      } else {
        chunks.push(data);
      }
      // opcode
    } else {
      chunks.push(opcode);
      i += 1;
    }
  }
  return chunks;
}
exports.decompile = decompile;
function toASM(chunks) {
  if (chunksIsBuffer(chunks)) {
    chunks = decompile(chunks);
  }
  return chunks
    .map(chunk => {
      // data?
      if (singleChunkIsBuffer(chunk)) {
        const op = asMinimalOP(chunk);
        if (op === undefined) return chunk.toString('hex');
        chunk = op;
      }
      // opcode!
      return map_1[chunk];
    })
    .join(' ');
}
exports.toASM = toASM;
function fromASM(asm) {
  typef(types.String, asm);
  return compile(
    asm.split(' ').map(chunkStr => {
      // opcode?
      if (exports.OPS[chunkStr] !== undefined) return exports.OPS[chunkStr];
      typef(types.Hex, chunkStr);
      // data!
      return Buffer$1.from(chunkStr, 'hex');
    }),
  );
}
exports.fromASM = fromASM;
function toStack(chunks) {
  chunks = decompile(chunks);
  typef(isPushOnly, chunks);
  return chunks.map(op => {
    if (singleChunkIsBuffer(op)) return op;
    if (op === exports.OPS.OP_0) return Buffer$1.allocUnsafe(0);
    return scriptNumber.encode(op - OP_INT_BASE);
  });
}
exports.toStack = toStack;
function isCanonicalPubKey(buffer) {
  return ecc.isPoint(buffer);
}
exports.isCanonicalPubKey = isCanonicalPubKey;
function isDefinedHashType(hashType) {
  const hashTypeMod = hashType & ~0x80;
  // return hashTypeMod > SIGHASH_ALL && hashTypeMod < SIGHASH_SINGLE
  return hashTypeMod > 0x00 && hashTypeMod < 0x04;
}
exports.isDefinedHashType = isDefinedHashType;
function isCanonicalScriptSignature(buffer) {
  if (!Buffer$1.isBuffer(buffer)) return false;
  if (!isDefinedHashType(buffer[buffer.length - 1])) return false;
  return bip66.check(buffer.slice(0, -1));
}
exports.isCanonicalScriptSignature = isCanonicalScriptSignature;
// tslint:disable-next-line variable-name
exports.number = scriptNumber;
exports.signature = scriptSignature;
});

function prop(object, name, f) {
  Object.defineProperty(object, name, {
    configurable: true,
    enumerable: true,
    get() {
      const _value = f.call(this);
      this[name] = _value;
      return _value;
    },
    set(_value) {
      Object.defineProperty(this, name, {
        configurable: true,
        enumerable: true,
        value: _value,
        writable: true,
      });
    },
  });
}
var prop_1 = prop;
function value(f) {
  let _value;
  return () => {
    if (_value !== undefined) return _value;
    _value = f();
    return _value;
  };
}
var value_1 = value;

var lazy$7 = /*#__PURE__*/Object.defineProperty({
	prop: prop_1,
	value: value_1
}, '__esModule', {value: true});

var __importStar$e =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };


const bscript$8 = __importStar$e(script$1);
const lazy$6 = __importStar$e(lazy$7);

const OPS$6 = bscript$8.OPS;
function stacksEqual$3(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}
// output: OP_RETURN ...
function p2data(a, opts) {
  if (!a.data && !a.output) throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  typef(
    {
      network: typef.maybe(typef.Object),
      output: typef.maybe(typef.Buffer),
      data: typef.maybe(typef.arrayOf(typef.Buffer)),
    },
    a,
  );
  const network = a.network || networks$2.liquid;
  const o = { name: 'embed', network };
  lazy$6.prop(o, 'output', () => {
    if (!a.data) return;
    return bscript$8.compile([OPS$6.OP_RETURN].concat(a.data));
  });
  lazy$6.prop(o, 'data', () => {
    if (!a.output) return;
    return bscript$8.decompile(a.output).slice(1);
  });
  // extended validation
  if (opts.validate) {
    if (a.output) {
      const chunks = bscript$8.decompile(a.output);
      if (chunks[0] !== OPS$6.OP_RETURN) throw new TypeError('Output is invalid');
      if (!chunks.slice(1).every(typef.Buffer))
        throw new TypeError('Output is invalid');
      if (a.data && !stacksEqual$3(a.data, o.data))
        throw new TypeError('Data mismatch');
    }
  }
  return Object.assign(o, a);
}
var p2data_1 = p2data;

var embed$1 = /*#__PURE__*/Object.defineProperty({
	p2data: p2data_1
}, '__esModule', {value: true});

var __importStar$d =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };


const bscript$7 = __importStar$d(script$1);
const lazy$5 = __importStar$d(lazy$7);
const OPS$5 = bscript$7.OPS;


const OP_INT_BASE = OPS$5.OP_RESERVED; // OP_1 - 1
function stacksEqual$2(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}
// input: OP_0 [signatures ...]
// output: m [pubKeys ...] n OP_CHECKMULTISIG
function p2ms$1(a, opts) {
  if (
    !a.input &&
    !a.output &&
    !(a.pubkeys && a.m !== undefined) &&
    !a.signatures
  )
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  function isAcceptableSignature(x) {
    return (
      bscript$7.isCanonicalScriptSignature(x) ||
      (opts.allowIncomplete && x === OPS$5.OP_0) !== undefined
    );
  }
  typef(
    {
      network: typef.maybe(typef.Object),
      m: typef.maybe(typef.Number),
      n: typef.maybe(typef.Number),
      output: typef.maybe(typef.Buffer),
      pubkeys: typef.maybe(typef.arrayOf(ecc.isPoint)),
      signatures: typef.maybe(typef.arrayOf(isAcceptableSignature)),
      input: typef.maybe(typef.Buffer),
    },
    a,
  );
  const network = a.network || networks$2.liquid;
  const o = { network };
  let chunks = [];
  let decoded = false;
  function decode(output) {
    if (decoded) return;
    decoded = true;
    chunks = bscript$7.decompile(output);
    o.m = chunks[0] - OP_INT_BASE;
    o.n = chunks[chunks.length - 2] - OP_INT_BASE;
    o.pubkeys = chunks.slice(1, -2);
  }
  lazy$5.prop(o, 'output', () => {
    if (!a.m) return;
    if (!o.n) return;
    if (!a.pubkeys) return;
    return bscript$7.compile(
      [].concat(
        OP_INT_BASE + a.m,
        a.pubkeys,
        OP_INT_BASE + o.n,
        OPS$5.OP_CHECKMULTISIG,
      ),
    );
  });
  lazy$5.prop(o, 'm', () => {
    if (!o.output) return;
    decode(o.output);
    return o.m;
  });
  lazy$5.prop(o, 'n', () => {
    if (!o.pubkeys) return;
    return o.pubkeys.length;
  });
  lazy$5.prop(o, 'pubkeys', () => {
    if (!a.output) return;
    decode(a.output);
    return o.pubkeys;
  });
  lazy$5.prop(o, 'signatures', () => {
    if (!a.input) return;
    return bscript$7.decompile(a.input).slice(1);
  });
  lazy$5.prop(o, 'input', () => {
    if (!a.signatures) return;
    return bscript$7.compile([OPS$5.OP_0].concat(a.signatures));
  });
  lazy$5.prop(o, 'witness', () => {
    if (!o.input) return;
    return [];
  });
  lazy$5.prop(o, 'name', () => {
    if (!o.m || !o.n) return;
    return `p2ms(${o.m} of ${o.n})`;
  });
  // extended validation
  if (opts.validate) {
    if (a.output) {
      decode(a.output);
      if (!typef.Number(chunks[0])) throw new TypeError('Output is invalid');
      if (!typef.Number(chunks[chunks.length - 2]))
        throw new TypeError('Output is invalid');
      if (chunks[chunks.length - 1] !== OPS$5.OP_CHECKMULTISIG)
        throw new TypeError('Output is invalid');
      if (o.m <= 0 || o.n > 16 || o.m > o.n || o.n !== chunks.length - 3)
        throw new TypeError('Output is invalid');
      if (!o.pubkeys.every(x => ecc.isPoint(x)))
        throw new TypeError('Output is invalid');
      if (a.m !== undefined && a.m !== o.m) throw new TypeError('m mismatch');
      if (a.n !== undefined && a.n !== o.n) throw new TypeError('n mismatch');
      if (a.pubkeys && !stacksEqual$2(a.pubkeys, o.pubkeys))
        throw new TypeError('Pubkeys mismatch');
    }
    if (a.pubkeys) {
      if (a.n !== undefined && a.n !== a.pubkeys.length)
        throw new TypeError('Pubkey count mismatch');
      o.n = a.pubkeys.length;
      if (o.n < o.m) throw new TypeError('Pubkey count cannot be less than m');
    }
    if (a.signatures) {
      if (a.signatures.length < o.m)
        throw new TypeError('Not enough signatures provided');
      if (a.signatures.length > o.m)
        throw new TypeError('Too many signatures provided');
    }
    if (a.input) {
      if (a.input[0] !== OPS$5.OP_0) throw new TypeError('Input is invalid');
      if (
        o.signatures.length === 0 ||
        !o.signatures.every(isAcceptableSignature)
      )
        throw new TypeError('Input has invalid signature(s)');
      if (a.signatures && !stacksEqual$2(a.signatures, o.signatures))
        throw new TypeError('Signature mismatch');
      if (a.m !== undefined && a.m !== a.signatures.length)
        throw new TypeError('Signature count mismatch');
    }
  }
  return Object.assign(o, a);
}
var p2ms_2 = p2ms$1;

var p2ms_1 = /*#__PURE__*/Object.defineProperty({
	p2ms: p2ms_2
}, '__esModule', {value: true});

var __importStar$c =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };


const bscript$6 = __importStar$c(script$1);
const lazy$4 = __importStar$c(lazy$7);

const OPS$4 = bscript$6.OPS;

// input: {signature}
// output: {pubKey} OP_CHECKSIG
function p2pk$1(a, opts) {
  if (!a.input && !a.output && !a.pubkey && !a.input && !a.signature)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  typef(
    {
      network: typef.maybe(typef.Object),
      output: typef.maybe(typef.Buffer),
      pubkey: typef.maybe(ecc.isPoint),
      signature: typef.maybe(bscript$6.isCanonicalScriptSignature),
      input: typef.maybe(typef.Buffer),
    },
    a,
  );
  const _chunks = lazy$4.value(() => {
    return bscript$6.decompile(a.input);
  });
  const network = a.network || networks$2.liquid;
  const o = { name: 'p2pk', network };
  lazy$4.prop(o, 'output', () => {
    if (!a.pubkey) return;
    return bscript$6.compile([a.pubkey, OPS$4.OP_CHECKSIG]);
  });
  lazy$4.prop(o, 'pubkey', () => {
    if (!a.output) return;
    return a.output.slice(1, -1);
  });
  lazy$4.prop(o, 'signature', () => {
    if (!a.input) return;
    return _chunks()[0];
  });
  lazy$4.prop(o, 'input', () => {
    if (!a.signature) return;
    return bscript$6.compile([a.signature]);
  });
  lazy$4.prop(o, 'witness', () => {
    if (!o.input) return;
    return [];
  });
  // extended validation
  if (opts.validate) {
    if (a.output) {
      if (a.output[a.output.length - 1] !== OPS$4.OP_CHECKSIG)
        throw new TypeError('Output is invalid');
      if (!ecc.isPoint(o.pubkey))
        throw new TypeError('Output pubkey is invalid');
      if (a.pubkey && !a.pubkey.equals(o.pubkey))
        throw new TypeError('Pubkey mismatch');
    }
    if (a.signature) {
      if (a.input && !a.input.equals(o.input))
        throw new TypeError('Signature mismatch');
    }
    if (a.input) {
      if (_chunks().length !== 1) throw new TypeError('Input is invalid');
      if (!bscript$6.isCanonicalScriptSignature(o.signature))
        throw new TypeError('Input has invalid signature');
    }
  }
  return Object.assign(o, a);
}
var p2pk_2 = p2pk$1;

var p2pk_1 = /*#__PURE__*/Object.defineProperty({
	p2pk: p2pk_2
}, '__esModule', {value: true});

function ripemd160(buffer) {
  try {
    return createHash('rmd160')
      .update(buffer)
      .digest();
  } catch (err) {
    return createHash('ripemd160')
      .update(buffer)
      .digest();
  }
}
var ripemd160_1 = ripemd160;
function sha1(buffer) {
  return createHash('sha1')
    .update(buffer)
    .digest();
}
var sha1_1 = sha1;
function sha256(buffer) {
  return createHash('sha256')
    .update(buffer)
    .digest();
}
var sha256_1 = sha256;
function hash160(buffer) {
  return ripemd160(sha256(buffer));
}
var hash160_1 = hash160;
function hash256(buffer) {
  return sha256(sha256(buffer));
}
var hash256_1 = hash256;

var crypto$2 = /*#__PURE__*/Object.defineProperty({
	ripemd160: ripemd160_1,
	sha1: sha1_1,
	sha256: sha256_1,
	hash160: hash160_1,
	hash256: hash256_1
}, '__esModule', {value: true});

var __importStar$b =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };

const bcrypto$5 = __importStar$b(crypto$2);

const bscript$5 = __importStar$b(script$1);
const lazy$3 = __importStar$b(lazy$7);

const OPS$3 = bscript$5.OPS;


// input: {signature} {pubkey}
// output: OP_DUP OP_HASH160 {hash160(pubkey)} OP_EQUALVERIFY OP_CHECKSIG
function p2pkh$1(a, opts) {
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.pubkey &&
    !a.input &&
    !a.confidentialAddress
  )
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  typef(
    {
      network: typef.maybe(typef.Object),
      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(20)),
      output: typef.maybe(typef.BufferN(25)),
      pubkey: typef.maybe(ecc.isPoint),
      signature: typef.maybe(bscript$5.isCanonicalScriptSignature),
      input: typef.maybe(typef.Buffer),
      blindkey: typef.maybe(ecc.isPoint),
      confidentialAddress: typef.maybe(typef.String),
    },
    a,
  );
  const _address = lazy$3.value(() => {
    const payload = bs58check.decode(a.address);
    const version = payload.readUInt8(0);
    const hash = payload.slice(1);
    return { version, hash };
  });
  const _chunks = lazy$3.value(() => {
    return bscript$5.decompile(a.input);
  });
  const _confidentialAddress = lazy$3.value(() => {
    const payload = bs58check.decode(a.confidentialAddress);
    const blindkey = payload.slice(2, 35);
    const unconfidentialAddressBuffer = Buffer$1.concat([
      Buffer$1.from([payload.readUInt8(1)]),
      payload.slice(35),
    ]);
    const unconfidentialAddress = bs58check.encode(unconfidentialAddressBuffer);
    return { blindkey, unconfidentialAddress };
  });
  const network = a.network || networks$2.liquid;
  const o = { name: 'p2pkh', network };
  lazy$3.prop(o, 'address', () => {
    if (!o.hash) return;
    const payload = Buffer$1.allocUnsafe(21);
    payload.writeUInt8(network.pubKeyHash, 0);
    o.hash.copy(payload, 1);
    return bs58check.encode(payload);
  });
  lazy$3.prop(o, 'hash', () => {
    if (a.output) return a.output.slice(3, 23);
    if (a.address) return _address().hash;
    if (a.pubkey || o.pubkey) return bcrypto$5.hash160(a.pubkey || o.pubkey);
    if (a.confidentialAddress) {
      const address = _confidentialAddress().unconfidentialAddress;
      return bs58check.decode(address).slice(1);
    }
  });
  lazy$3.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript$5.compile([
      OPS$3.OP_DUP,
      OPS$3.OP_HASH160,
      o.hash,
      OPS$3.OP_EQUALVERIFY,
      OPS$3.OP_CHECKSIG,
    ]);
  });
  lazy$3.prop(o, 'pubkey', () => {
    if (!a.input) return;
    return _chunks()[1];
  });
  lazy$3.prop(o, 'signature', () => {
    if (!a.input) return;
    return _chunks()[0];
  });
  lazy$3.prop(o, 'input', () => {
    if (!a.pubkey) return;
    if (!a.signature) return;
    return bscript$5.compile([a.signature, a.pubkey]);
  });
  lazy$3.prop(o, 'witness', () => {
    if (!o.input) return;
    return [];
  });
  lazy$3.prop(o, 'blindkey', () => {
    if (a.confidentialAddress) return _confidentialAddress().blindkey;
    if (a.blindkey) return a.blindkey;
  });
  lazy$3.prop(o, 'confidentialAddress', () => {
    if (!o.address) return;
    if (!o.blindkey) return;
    const payload = bs58check.decode(o.address);
    const confidentialAddress = Buffer$1.concat([
      Buffer$1.from([network.confidentialPrefix, payload.readUInt8(0)]),
      o.blindkey,
      Buffer$1.from(payload.slice(1)),
    ]);
    return bs58check.encode(confidentialAddress);
  });
  // extended validation
  if (opts.validate) {
    let hash = Buffer$1.from([]);
    let blindkey = Buffer$1.from([]);
    if (a.address) {
      if (_address().version !== network.pubKeyHash)
        throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      hash = _address().hash;
    }
    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }
    if (a.output) {
      if (
        a.output.length !== 25 ||
        a.output[0] !== OPS$3.OP_DUP ||
        a.output[1] !== OPS$3.OP_HASH160 ||
        a.output[2] !== 0x14 ||
        a.output[23] !== OPS$3.OP_EQUALVERIFY ||
        a.output[24] !== OPS$3.OP_CHECKSIG
      )
        throw new TypeError('Output is invalid');
      const hash2 = a.output.slice(3, 23);
      if (hash.length > 0 && !hash.equals(hash2))
        throw new TypeError('Hash mismatch');
      else hash = hash2;
    }
    if (a.pubkey) {
      const pkh = bcrypto$5.hash160(a.pubkey);
      if (hash.length > 0 && !hash.equals(pkh))
        throw new TypeError('Hash mismatch');
      else hash = pkh;
    }
    if (a.input) {
      const chunks = _chunks();
      if (chunks.length !== 2) throw new TypeError('Input is invalid');
      if (!bscript$5.isCanonicalScriptSignature(chunks[0]))
        throw new TypeError('Input has invalid signature');
      if (!ecc.isPoint(chunks[1]))
        throw new TypeError('Input has invalid pubkey');
      if (a.signature && !a.signature.equals(chunks[0]))
        throw new TypeError('Signature mismatch');
      if (a.pubkey && !a.pubkey.equals(chunks[1]))
        throw new TypeError('Pubkey mismatch');
      const pkh = bcrypto$5.hash160(chunks[1]);
      if (hash.length > 0 && !hash.equals(pkh))
        throw new TypeError('Hash mismatch');
    }
    if (a.confidentialAddress) {
      if (
        a.address &&
        a.address !== _confidentialAddress().unconfidentialAddress
      )
        throw new TypeError('Address mismatch');
      if (
        blindkey.length > 0 &&
        !blindkey.equals(_confidentialAddress().blindkey)
      )
        throw new TypeError('Blindkey mismatch');
      else blindkey = _confidentialAddress().blindkey;
    }
    if (a.blindkey) {
      if (!ecc.isPoint(a.blindkey)) throw new TypeError('Blindkey is invalid');
      if (blindkey.length > 0 && !blindkey.equals(a.blindkey))
        throw new TypeError('Blindkey mismatch');
      else blindkey = a.blindkey;
    }
  }
  return Object.assign(o, a);
}
var p2pkh_2 = p2pkh$1;

var p2pkh_1 = /*#__PURE__*/Object.defineProperty({
	p2pkh: p2pkh_2
}, '__esModule', {value: true});

var __importStar$a =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };

const bcrypto$4 = __importStar$a(crypto$2);

const bscript$4 = __importStar$a(script$1);
const lazy$2 = __importStar$a(lazy$7);

const OPS$2 = bscript$4.OPS;


function stacksEqual$1(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}
// input: [redeemScriptSig ...] {redeemScript}
// witness: <?>
// output: OP_HASH160 {hash160(redeemScript)} OP_EQUAL
function p2sh$1(a, opts) {
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.redeem &&
    !a.input &&
    !a.confidentialAddress
  )
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  typef(
    {
      network: typef.maybe(typef.Object),
      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(20)),
      output: typef.maybe(typef.BufferN(23)),
      redeem: typef.maybe({
        network: typef.maybe(typef.Object),
        output: typef.maybe(typef.Buffer),
        input: typef.maybe(typef.Buffer),
        witness: typef.maybe(typef.arrayOf(typef.Buffer)),
      }),
      input: typef.maybe(typef.Buffer),
      witness: typef.maybe(typef.arrayOf(typef.Buffer)),
      blindkey: typef.maybe(ecc.isPoint),
      confidentialAddress: typef.maybe(typef.String),
    },
    a,
  );
  let network = a.network;
  if (!network) {
    network = (a.redeem && a.redeem.network) || networks$2.liquid;
  }
  const o = { network };
  const _address = lazy$2.value(() => {
    const payload = bs58check.decode(a.address);
    const version = payload.readUInt8(0);
    const hash = payload.slice(1);
    return { version, hash };
  });
  const _chunks = lazy$2.value(() => {
    return bscript$4.decompile(a.input);
  });
  const _redeem = lazy$2.value(() => {
    const chunks = _chunks();
    return {
      network,
      output: chunks[chunks.length - 1],
      input: bscript$4.compile(chunks.slice(0, -1)),
      witness: a.witness || [],
    };
  });
  const _confidentialAddress = lazy$2.value(() => {
    const payload = bs58check.decode(a.confidentialAddress);
    const blindkey = payload.slice(2, 35);
    const unconfidentialAddressBuffer = Buffer$1.concat([
      Buffer$1.from([payload.readUInt8(1)]),
      payload.slice(35),
    ]);
    const unconfidentialAddress = bs58check.encode(unconfidentialAddressBuffer);
    return { blindkey, unconfidentialAddress };
  });
  // output dependents
  lazy$2.prop(o, 'address', () => {
    if (!o.hash) return;
    const payload = Buffer$1.allocUnsafe(21);
    payload.writeUInt8(o.network.scriptHash, 0);
    o.hash.copy(payload, 1);
    return bs58check.encode(payload);
  });
  lazy$2.prop(o, 'hash', () => {
    // in order of least effort
    if (a.output) return a.output.slice(2, 22);
    if (a.address) return _address().hash;
    if (o.redeem && o.redeem.output) return bcrypto$4.hash160(o.redeem.output);
    if (a.confidentialAddress) {
      const address = _confidentialAddress().unconfidentialAddress;
      return bs58check.decode(address).slice(1);
    }
  });
  lazy$2.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript$4.compile([OPS$2.OP_HASH160, o.hash, OPS$2.OP_EQUAL]);
  });
  // input dependents
  lazy$2.prop(o, 'redeem', () => {
    if (!a.input) return;
    return _redeem();
  });
  lazy$2.prop(o, 'input', () => {
    if (!a.redeem || !a.redeem.input || !a.redeem.output) return;
    return bscript$4.compile(
      [].concat(bscript$4.decompile(a.redeem.input), a.redeem.output),
    );
  });
  lazy$2.prop(o, 'witness', () => {
    if (o.redeem && o.redeem.witness) return o.redeem.witness;
    if (o.input) return [];
  });
  lazy$2.prop(o, 'name', () => {
    const nameParts = ['p2sh'];
    if (o.redeem !== undefined) nameParts.push(o.redeem.name);
    return nameParts.join('-');
  });
  lazy$2.prop(o, 'blindkey', () => {
    if (a.confidentialAddress) return _confidentialAddress().blindkey;
    if (a.blindkey) return a.blindkey;
  });
  lazy$2.prop(o, 'confidentialAddress', () => {
    if (!o.address) return;
    if (!o.blindkey) return;
    const payload = bs58check.decode(o.address);
    const confidentialAddress = Buffer$1.concat([
      Buffer$1.from([network.confidentialPrefix, payload.readUInt8(0)]),
      o.blindkey,
      Buffer$1.from(payload.slice(1)),
    ]);
    return bs58check.encode(confidentialAddress);
  });
  if (opts.validate) {
    let hash = Buffer$1.from([]);
    let blindkey = Buffer$1.from([]);
    if (a.address) {
      if (_address().version !== network.scriptHash)
        throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      hash = _address().hash;
    }
    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }
    if (a.output) {
      if (
        a.output.length !== 23 ||
        a.output[0] !== OPS$2.OP_HASH160 ||
        a.output[1] !== 0x14 ||
        a.output[22] !== OPS$2.OP_EQUAL
      )
        throw new TypeError('Output is invalid');
      const hash2 = a.output.slice(2, 22);
      if (hash.length > 0 && !hash.equals(hash2))
        throw new TypeError('Hash mismatch');
      else hash = hash2;
    }
    // inlined to prevent 'no-inner-declarations' failing
    const checkRedeem = redeem => {
      // is the redeem output empty/invalid?
      if (redeem.output) {
        const decompile = bscript$4.decompile(redeem.output);
        if (!decompile || decompile.length < 1)
          throw new TypeError('Redeem.output too short');
        // match hash against other sources
        const hash2 = bcrypto$4.hash160(redeem.output);
        if (hash.length > 0 && !hash.equals(hash2))
          throw new TypeError('Hash mismatch');
        else hash = hash2;
      }
      if (redeem.input) {
        const hasInput = redeem.input.length > 0;
        const hasWitness = redeem.witness && redeem.witness.length > 0;
        if (!hasInput && !hasWitness) throw new TypeError('Empty input');
        if (hasInput && hasWitness)
          throw new TypeError('Input and witness provided');
        if (hasInput) {
          const richunks = bscript$4.decompile(redeem.input);
          if (!bscript$4.isPushOnly(richunks))
            throw new TypeError('Non push-only scriptSig');
        }
      }
    };
    if (a.input) {
      const chunks = _chunks();
      if (!chunks || chunks.length < 1) throw new TypeError('Input too short');
      if (!Buffer$1.isBuffer(_redeem().output))
        throw new TypeError('Input is invalid');
      checkRedeem(_redeem());
    }
    if (a.redeem) {
      if (a.redeem.network && a.redeem.network !== network)
        throw new TypeError('Network mismatch');
      if (a.input) {
        const redeem = _redeem();
        if (a.redeem.output && !a.redeem.output.equals(redeem.output))
          throw new TypeError('Redeem.output mismatch');
        if (a.redeem.input && !a.redeem.input.equals(redeem.input))
          throw new TypeError('Redeem.input mismatch');
      }
      checkRedeem(a.redeem);
    }
    if (a.witness) {
      if (
        a.redeem &&
        a.redeem.witness &&
        !stacksEqual$1(a.redeem.witness, a.witness)
      )
        throw new TypeError('Witness and redeem.witness mismatch');
    }
    if (a.confidentialAddress) {
      if (
        a.address &&
        a.address !== _confidentialAddress().unconfidentialAddress
      )
        throw new TypeError('Address mismatch');
      if (
        blindkey.length > 0 &&
        !blindkey.equals(_confidentialAddress().blindkey)
      )
        throw new TypeError('Blindkey mismatch');
      else blindkey = _confidentialAddress().blindkey;
    }
    if (a.blindkey) {
      if (!ecc.isPoint(a.blindkey)) throw new TypeError('Blindkey is invalid');
      if (blindkey.length > 0 && !blindkey.equals(a.blindkey))
        throw new TypeError('Blindkey mismatch');
      else blindkey = a.blindkey;
    }
  }
  return Object.assign(o, a);
}
var p2sh_2 = p2sh$1;

var p2sh_1 = /*#__PURE__*/Object.defineProperty({
	p2sh: p2sh_2
}, '__esModule', {value: true});

var __importStar$9 =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };

const bcrypto$3 = __importStar$9(crypto$2);

const bscript$3 = __importStar$9(script$1);
const lazy$1 = __importStar$9(lazy$7);

const OPS$1 = bscript$3.OPS;


const EMPTY_BUFFER$1 = Buffer$1.alloc(0);
// witness: {signature} {pubKey}
// input: <>
// output: OP_0 {pubKeyHash}
function p2wpkh$1(a, opts) {
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.pubkey &&
    !a.witness &&
    !a.confidentialAddress
  )
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  typef(
    {
      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(20)),
      input: typef.maybe(typef.BufferN(0)),
      network: typef.maybe(typef.Object),
      output: typef.maybe(typef.BufferN(22)),
      pubkey: typef.maybe(ecc.isPoint),
      signature: typef.maybe(bscript$3.isCanonicalScriptSignature),
      witness: typef.maybe(typef.arrayOf(typef.Buffer)),
    },
    a,
  );
  const network = a.network || networks$2.liquid;
  const _address = lazy$1.value(() => {
    const result = bech32.decode(a.address);
    const version = result.words.shift();
    const data = bech32.fromWords(result.words);
    return {
      version,
      prefix: result.prefix,
      data: Buffer$1.from(data),
    };
  });
  const o = { name: 'p2wpkh', network };
  lazy$1.prop(o, 'address', () => {
    if (!o.hash) return;
    const words = bech32.toWords(o.hash);
    words.unshift(0x00);
    return bech32.encode(network.bech32, words);
  });
  lazy$1.prop(o, 'hash', () => {
    if (a.output) return a.output.slice(2, 22);
    if (a.address) return _address().data;
    if (a.pubkey || o.pubkey) return bcrypto$3.hash160(a.pubkey || o.pubkey);
  });
  lazy$1.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript$3.compile([OPS$1.OP_0, o.hash]);
  });
  lazy$1.prop(o, 'pubkey', () => {
    if (a.pubkey) return a.pubkey;
    if (!a.witness) return;
    return a.witness[1];
  });
  lazy$1.prop(o, 'signature', () => {
    if (!a.witness) return;
    return a.witness[0];
  });
  lazy$1.prop(o, 'input', () => {
    if (!o.witness) return;
    return EMPTY_BUFFER$1;
  });
  lazy$1.prop(o, 'witness', () => {
    if (!a.pubkey) return;
    if (!a.signature) return;
    return [a.signature, a.pubkey];
  });
  lazy$1.prop(o, 'blindkey', () => {
    if (a.blindkey) return a.blindkey;
  });
  // extended validation
  if (opts.validate) {
    let hash = Buffer$1.from([]);
    let blindkey = Buffer$1.from([]);
    if (a.address) {
      if (network && network.bech32 !== _address().prefix)
        throw new TypeError('Invalid prefix or Network mismatch');
      if (_address().version !== 0x00)
        throw new TypeError('Invalid address version');
      if (_address().data.length !== 20)
        throw new TypeError('Invalid address data');
      hash = _address().data;
    }
    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }
    if (a.output) {
      if (
        a.output.length !== 22 ||
        a.output[0] !== OPS$1.OP_0 ||
        a.output[1] !== 0x14
      )
        throw new TypeError('Output is invalid');
      if (hash.length > 0 && !hash.equals(a.output.slice(2)))
        throw new TypeError('Hash mismatch');
      else hash = a.output.slice(2);
    }
    if (a.pubkey) {
      const pkh = bcrypto$3.hash160(a.pubkey);
      if (hash.length > 0 && !hash.equals(pkh))
        throw new TypeError('Hash mismatch');
      else hash = pkh;
    }
    if (a.witness) {
      if (a.witness.length !== 2) throw new TypeError('Witness is invalid');
      if (!bscript$3.isCanonicalScriptSignature(a.witness[0]))
        throw new TypeError('Witness has invalid signature');
      if (!ecc.isPoint(a.witness[1]))
        throw new TypeError('Witness has invalid pubkey');
      if (a.signature && !a.signature.equals(a.witness[0]))
        throw new TypeError('Signature mismatch');
      if (a.pubkey && !a.pubkey.equals(a.witness[1]))
        throw new TypeError('Pubkey mismatch');
      const pkh = bcrypto$3.hash160(a.witness[1]);
      if (hash.length > 0 && !hash.equals(pkh))
        throw new TypeError('Hash mismatch');
    }
    if (a.blindkey) {
      if (!ecc.isPoint(a.blindkey)) throw new TypeError('Blindkey is invalid');
      if (blindkey.length > 0 && !blindkey.equals(a.blindkey))
        throw new TypeError('Blindkey mismatch');
      else blindkey = a.blindkey;
    }
  }
  return Object.assign(o, a);
}
var p2wpkh_2 = p2wpkh$1;

var p2wpkh_1 = /*#__PURE__*/Object.defineProperty({
	p2wpkh: p2wpkh_2
}, '__esModule', {value: true});

var __importStar$8 =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };

const bcrypto$2 = __importStar$8(crypto$2);

const bscript$2 = __importStar$8(script$1);
const lazy = __importStar$8(lazy$7);

const OPS = bscript$2.OPS;


const EMPTY_BUFFER = Buffer$1.alloc(0);
function stacksEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}
// input: <>
// witness: [redeemScriptSig ...] {redeemScript}
// output: OP_0 {sha256(redeemScript)}
function p2wsh$1(a, opts) {
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.redeem &&
    !a.witness &&
    !a.confidentialAddress
  )
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  typef(
    {
      network: typef.maybe(typef.Object),
      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(32)),
      output: typef.maybe(typef.BufferN(34)),
      redeem: typef.maybe({
        input: typef.maybe(typef.Buffer),
        network: typef.maybe(typef.Object),
        output: typef.maybe(typef.Buffer),
        witness: typef.maybe(typef.arrayOf(typef.Buffer)),
      }),
      input: typef.maybe(typef.BufferN(0)),
      witness: typef.maybe(typef.arrayOf(typef.Buffer)),
      blindkey: typef.maybe(ecc.isPoint),
      confidentialAddress: typef.maybe(typef.String),
    },
    a,
  );
  let network = a.network;
  if (!network) {
    network = (a.redeem && a.redeem.network) || networks$2.liquid;
  }
  const _address = lazy.value(() => {
    const result = bech32.decode(a.address);
    const version = result.words.shift();
    const data = bech32.fromWords(result.words);
    return {
      version,
      prefix: result.prefix,
      data: Buffer$1.from(data),
    };
  });
  const _rchunks = lazy.value(() => {
    return bscript$2.decompile(a.redeem.input);
  });
  const o = { network };
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;
    const words = bech32.toWords(o.hash);
    words.unshift(0x00);
    return bech32.encode(network.bech32, words);
  });
  lazy.prop(o, 'hash', () => {
    if (a.output) return a.output.slice(2);
    if (a.address) return _address().data;
    if (o.redeem && o.redeem.output) return bcrypto$2.sha256(o.redeem.output);
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript$2.compile([OPS.OP_0, o.hash]);
  });
  lazy.prop(o, 'redeem', () => {
    if (!a.witness) return;
    return {
      output: a.witness[a.witness.length - 1],
      input: EMPTY_BUFFER,
      witness: a.witness.slice(0, -1),
    };
  });
  lazy.prop(o, 'input', () => {
    if (!o.witness) return;
    return EMPTY_BUFFER;
  });
  lazy.prop(o, 'witness', () => {
    // transform redeem input to witness stack?
    if (
      a.redeem &&
      a.redeem.input &&
      a.redeem.input.length > 0 &&
      a.redeem.output &&
      a.redeem.output.length > 0
    ) {
      const stack = bscript$2.toStack(_rchunks());
      // assign, and blank the existing input
      o.redeem = Object.assign({ witness: stack }, a.redeem);
      o.redeem.input = EMPTY_BUFFER;
      return [].concat(stack, a.redeem.output);
    }
    if (!a.redeem) return;
    if (!a.redeem.output) return;
    if (!a.redeem.witness) return;
    return [].concat(a.redeem.witness, a.redeem.output);
  });
  lazy.prop(o, 'name', () => {
    const nameParts = ['p2wsh'];
    if (o.redeem !== undefined) nameParts.push(o.redeem.name);
    return nameParts.join('-');
  });
  lazy.prop(o, 'blindkey', () => {
    if (a.blindkey) return a.blindkey;
  });
  // extended validation
  if (opts.validate) {
    let hash = Buffer$1.from([]);
    let blindkey = Buffer$1.from([]);
    if (a.address) {
      if (_address().prefix !== network.bech32)
        throw new TypeError('Invalid prefix or Network mismatch');
      if (_address().version !== 0x00)
        throw new TypeError('Invalid address version');
      if (_address().data.length !== 32)
        throw new TypeError('Invalid address data');
      hash = _address().data;
    }
    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }
    if (a.output) {
      if (
        a.output.length !== 34 ||
        a.output[0] !== OPS.OP_0 ||
        a.output[1] !== 0x20
      )
        throw new TypeError('Output is invalid');
      const hash2 = a.output.slice(2);
      if (hash.length > 0 && !hash.equals(hash2))
        throw new TypeError('Hash mismatch');
      else hash = hash2;
    }
    if (a.redeem) {
      if (a.redeem.network && a.redeem.network !== network)
        throw new TypeError('Network mismatch');
      // is there two redeem sources?
      if (
        a.redeem.input &&
        a.redeem.input.length > 0 &&
        a.redeem.witness &&
        a.redeem.witness.length > 0
      )
        throw new TypeError('Ambiguous witness source');
      // is the redeem output non-empty?
      if (a.redeem.output) {
        if (bscript$2.decompile(a.redeem.output).length === 0)
          throw new TypeError('Redeem.output is invalid');
        // match hash against other sources
        const hash2 = bcrypto$2.sha256(a.redeem.output);
        if (hash.length > 0 && !hash.equals(hash2))
          throw new TypeError('Hash mismatch');
        else hash = hash2;
      }
      if (a.redeem.input && !bscript$2.isPushOnly(_rchunks()))
        throw new TypeError('Non push-only scriptSig');
      if (
        a.witness &&
        a.redeem.witness &&
        !stacksEqual(a.witness, a.redeem.witness)
      )
        throw new TypeError('Witness and redeem.witness mismatch');
    }
    if (a.witness) {
      if (
        a.redeem &&
        a.redeem.output &&
        !a.redeem.output.equals(a.witness[a.witness.length - 1])
      )
        throw new TypeError('Witness and redeem.output mismatch');
    }
    if (a.blindkey) {
      if (!ecc.isPoint(a.blindkey)) throw new TypeError('Blindkey is invalid');
      if (blindkey.length > 0 && !blindkey.equals(a.blindkey))
        throw new TypeError('Blindkey mismatch');
      else blindkey = a.blindkey;
    }
  }
  return Object.assign(o, a);
}
var p2wsh_2 = p2wsh$1;

var p2wsh_1 = /*#__PURE__*/Object.defineProperty({
	p2wsh: p2wsh_2
}, '__esModule', {value: true});

var embed = embed$1.p2data;

var p2ms = p2ms_1.p2ms;

var p2pk = p2pk_1.p2pk;

var p2pkh = p2pkh_1.p2pkh;

var p2sh = p2sh_1.p2sh;

var p2wpkh = p2wpkh_1.p2wpkh;

var p2wsh = p2wsh_1.p2wsh;
// TODO
// witness commitment

var payments$3 = /*#__PURE__*/Object.defineProperty({
	embed: embed,
	p2ms: p2ms,
	p2pk: p2pk,
	p2pkh: p2pkh,
	p2sh: p2sh,
	p2wpkh: p2wpkh,
	p2wsh: p2wsh
}, '__esModule', {value: true});

var __importStar$7 =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };

const networks$1 = __importStar$7(networks$2);
const payments$2 = __importStar$7(payments$3);
const bscript$1 = __importStar$7(script$1);
const types$3 = __importStar$7(types$5);



function fromBase58Check(address) {
  const payload = bs58check.decode(address);
  // TODO: 4.0.0, move to "toOutputScript"
  if (payload.length < 21) throw new TypeError(address + ' is too short');
  if (payload.length > 21) throw new TypeError(address + ' is too long');
  const version = payload.readUInt8(0);
  const hash = payload.slice(1);
  return { version, hash };
}
var fromBase58Check_1 = fromBase58Check;
function fromBech32(address) {
  const result = bech32.decode(address);
  const data = bech32.fromWords(result.words.slice(1));
  return {
    version: result.words[0],
    prefix: result.prefix,
    data: Buffer$1.from(data),
  };
}
var fromBech32_1 = fromBech32;
function fromConfidential(address) {
  const network = getNetwork(address);
  return fromConfidentialLegacy(address, network);
}
var fromConfidential_1 = fromConfidential;
function toBase58Check(hash, version) {
  typef(types$3.tuple(types$3.Hash160bit, types$3.UInt8), arguments);
  const payload = Buffer$1.allocUnsafe(21);
  payload.writeUInt8(version, 0);
  hash.copy(payload, 1);
  return bs58check.encode(payload);
}
var toBase58Check_1 = toBase58Check;
function toBech32(data, version, prefix) {
  const words = bech32.toWords(data);
  words.unshift(version);
  return bech32.encode(prefix, words);
}
var toBech32_1 = toBech32;
function toConfidential(address, blindingKey) {
  const network = getNetwork(address);
  return toConfidentialLegacy(address, blindingKey, network);
}
var toConfidential_1 = toConfidential;
function fromOutputScript(output, network) {
  // TODO: Network
  network = network || networks$1.liquid;
  try {
    return payments$2.p2pkh({ output, network }).address;
  } catch (e) {}
  try {
    return payments$2.p2sh({ output, network }).address;
  } catch (e) {}
  try {
    return payments$2.p2wpkh({ output, network }).address;
  } catch (e) {}
  try {
    return payments$2.p2wsh({ output, network }).address;
  } catch (e) {}
  throw new Error(bscript$1.toASM(output) + ' has no matching Address');
}
var fromOutputScript_1 = fromOutputScript;
function toOutputScript(address, network) {
  network = network || getNetwork(address);
  let decodeBase58;
  let decodeBech32;
  let decodeConfidential;
  try {
    decodeBase58 = fromBase58Check(address);
  } catch (e) {}
  if (decodeBase58) {
    if (decodeBase58.version === network.pubKeyHash)
      return payments$2.p2pkh({ hash: decodeBase58.hash }).output;
    if (decodeBase58.version === network.scriptHash)
      return payments$2.p2sh({ hash: decodeBase58.hash }).output;
  } else {
    try {
      decodeBech32 = fromBech32(address);
    } catch (e) {}
    if (decodeBech32) {
      if (decodeBech32.prefix !== network.bech32)
        throw new Error(address + ' has an invalid prefix');
      if (decodeBech32.version === 0) {
        if (decodeBech32.data.length === 20)
          return payments$2.p2wpkh({ hash: decodeBech32.data }).output;
        if (decodeBech32.data.length === 32)
          return payments$2.p2wsh({ hash: decodeBech32.data }).output;
      }
    } else {
      try {
        decodeConfidential = fromConfidential(address);
      } catch (e) {}
      if (decodeConfidential) {
        return toOutputScript(
          decodeConfidential.unconfidentialAddress,
          network,
        );
      }
    }
  }
  throw new Error(address + ' has no matching Script');
}
var toOutputScript_1 = toOutputScript;
function getNetwork(address) {
  if (
    address.startsWith(networks$1.liquid.blech32) ||
    address.startsWith(networks$1.liquid.bech32)
  )
    return networks$1.liquid;
  if (
    address.startsWith(networks$1.regtest.blech32) ||
    address.startsWith(networks$1.regtest.bech32)
  )
    return networks$1.regtest;
  const payload = bs58check.decode(address);
  const prefix = payload.readUInt8(0);
  if (
    prefix === networks$1.liquid.confidentialPrefix ||
    prefix === networks$1.liquid.pubKeyHash ||
    prefix === networks$1.liquid.scriptHash
  )
    return networks$1.liquid;
  if (
    prefix === networks$1.regtest.confidentialPrefix ||
    prefix === networks$1.regtest.pubKeyHash ||
    prefix === networks$1.regtest.scriptHash
  )
    return networks$1.regtest;
  throw new Error(address + ' has an invalid prefix');
}
var getNetwork_1 = getNetwork;
function fromConfidentialLegacy(address, network) {
  const payload = bs58check.decode(address);
  const prefix = payload.readUInt8(1);
  // Check if address has valid length and prefix
  if (prefix !== network.pubKeyHash && prefix !== network.scriptHash)
    throw new TypeError(address + 'is not valid');
  if (payload.length < 55) throw new TypeError(address + ' is too short');
  if (payload.length > 55) throw new TypeError(address + ' is too long');
  // Blinded decoded haddress has the form:
  // BLIND_PREFIX|ADDRESS_PREFIX|BLINDING_KEY|SCRIPT_HASH
  // Prefixes are 1 byte long, thus blinding key always starts at 3rd byte
  const blindingKey = payload.slice(2, 35);
  const unconfidential = payload.slice(35, payload.length);
  const versionBuf = Buffer$1.alloc(1);
  versionBuf[0] = prefix;
  const unconfidentialAddressBuffer = Buffer$1.concat([
    versionBuf,
    unconfidential,
  ]);
  const unconfidentialAddress = bs58check.encode(unconfidentialAddressBuffer);
  return { blindingKey, unconfidentialAddress };
}
function toConfidentialLegacy(address, blindingKey, network) {
  const payload = bs58check.decode(address);
  const prefix = payload.readUInt8(0);
  // Check if address has valid length and prefix
  if (
    payload.length !== 21 ||
    (prefix !== network.pubKeyHash && prefix !== network.scriptHash)
  )
    throw new TypeError(address + 'is not valid');
  // Check if blind key has valid length
  if (blindingKey.length < 33) throw new TypeError('Blinding key is too short');
  if (blindingKey.length > 33) throw new TypeError('Blinding key is too long');
  const prefixBuf = Buffer$1.alloc(2);
  prefixBuf[0] = network.confidentialPrefix;
  prefixBuf[1] = prefix;
  const confidentialAddress = Buffer$1.concat([
    prefixBuf,
    blindingKey,
    Buffer$1.from(payload.slice(1)),
  ]);
  return bs58check.encode(confidentialAddress);
}
/**
 * A quick check used to verify if a string could be a confidential segwit address.
 * @param address address to test.
 */
function isConfidentialSegwit(address) {
  if (address.length !== 80) return false;
  if (address.startsWith('Az')) return true;
  return false;
}
/**
 * A quick check function used to verify if a string could be a valid confidential legacy address.
 * @param address address to test.
 */
function isConfidentialLegacy(address) {
  if (address.length !== 80) return false;
  if (address.startsWith('CTE')) return true;
  return false;
}
/**
 * A quick check used to verify if a string could be a valid confidential address.
 * @param address address to check.
 */
function isConfidential(address) {
  return isConfidentialLegacy(address) || isConfidentialSegwit(address);
}
var isConfidential_1 = isConfidential;

var address$1 = /*#__PURE__*/Object.defineProperty({
	fromBase58Check: fromBase58Check_1,
	fromBech32: fromBech32_1,
	fromConfidential: fromConfidential_1,
	toBase58Check: toBase58Check_1,
	toBech32: toBech32_1,
	toConfidential: toConfidential_1,
	fromOutputScript: fromOutputScript_1,
	toOutputScript: toOutputScript_1,
	getNetwork: getNetwork_1,
	isConfidential: isConfidential_1
}, '__esModule', {value: true});

var __importStar$6 =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };

const types$2 = __importStar$6(types$5);


const CONFIDENTIAL_COMMITMENT = 33; // default size of confidential commitments (i.e. asset, value, nonce)
const CONFIDENTIAL_VALUE$1 = 9; // explicit size of confidential values
// https://github.com/feross/buffer/blob/master/index.js#L1127
function verifuint(value, max) {
  if (typeof value !== 'number')
    throw new Error('cannot write a non-number as a number');
  if (value < 0)
    throw new Error('specified a negative value for writing an unsigned value');
  if (value > max) throw new Error('RangeError: value out of range');
  if (Math.floor(value) !== value)
    throw new Error('value has a fractional component');
}
function readUInt64LE(buffer, offset) {
  const a = buffer.readUInt32LE(offset);
  let b = buffer.readUInt32LE(offset + 4);
  b *= 0x100000000;
  verifuint(b + a, 0x001fffffffffffff);
  return b + a;
}
var readUInt64LE_1 = readUInt64LE;
function writeUInt64LE(buffer, value, offset) {
  verifuint(value, 0x001fffffffffffff);
  buffer.writeInt32LE(value & -1, offset);
  buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4);
  return offset + 8;
}
var writeUInt64LE_1 = writeUInt64LE;
function reverseBuffer(buffer) {
  if (buffer.length < 1) return buffer;
  let j = buffer.length - 1;
  let tmp = 0;
  for (let i = 0; i < buffer.length / 2; i++) {
    tmp = buffer[i];
    buffer[i] = buffer[j];
    buffer[j] = tmp;
    j--;
  }
  return buffer;
}
var reverseBuffer_1 = reverseBuffer;
/**
 * Helper class for serialization of bitcoin data types into a pre-allocated buffer.
 */
class BufferWriter {
  constructor(buffer, offset = 0) {
    this.buffer = buffer;
    this.offset = offset;
    typef(types$2.tuple(types$2.Buffer, types$2.UInt32), [buffer, offset]);
  }
  writeUInt8(i) {
    this.offset = this.buffer.writeUInt8(i, this.offset);
  }
  writeInt32(i) {
    this.offset = this.buffer.writeInt32LE(i, this.offset);
  }
  writeUInt32(i) {
    this.offset = this.buffer.writeUInt32LE(i, this.offset);
  }
  writeUInt64(i) {
    this.offset = writeUInt64LE(this.buffer, i, this.offset);
  }
  writeVarInt(i) {
    varuint$1.encode(i, this.buffer, this.offset);
    this.offset += varuint$1.encode.bytes;
  }
  writeSlice(slice) {
    if (this.buffer.length < this.offset + slice.length) {
      throw new Error('Cannot write slice out of bounds');
    }
    this.offset += slice.copy(this.buffer, this.offset);
  }
  writeVarSlice(slice) {
    this.writeVarInt(slice.length);
    this.writeSlice(slice);
  }
  writeVector(vector) {
    this.writeVarInt(vector.length);
    vector.forEach(buf => this.writeVarSlice(buf));
  }
  writeConfidentialInFields(input) {
    this.writeVarSlice(input.issuanceRangeProof);
    this.writeVarSlice(input.inflationRangeProof);
    this.writeVarInt(input.witness.length);
    for (const it of input.witness) this.writeVarSlice(it);
    this.writeVarInt(input.peginWitness.length);
    for (const it of input.peginWitness) this.writeVarSlice(it);
  }
  writeConfidentialOutFields(output) {
    this.writeVarSlice(output.surjectionProof);
    this.writeVarSlice(output.rangeProof);
  }
}
var BufferWriter_1 = BufferWriter;
/**
 * Helper class for reading of bitcoin data types from a buffer.
 */
class BufferReader {
  constructor(buffer, offset = 0) {
    this.buffer = buffer;
    this.offset = offset;
    typef(types$2.tuple(types$2.Buffer, types$2.UInt32), [buffer, offset]);
  }
  readUInt8() {
    const result = this.buffer.readUInt8(this.offset);
    this.offset++;
    return result;
  }
  readInt32() {
    const result = this.buffer.readInt32LE(this.offset);
    this.offset += 4;
    return result;
  }
  readUInt32() {
    const result = this.buffer.readUInt32LE(this.offset);
    this.offset += 4;
    return result;
  }
  readUInt64() {
    const result = readUInt64LE(this.buffer, this.offset);
    this.offset += 8;
    return result;
  }
  readVarInt() {
    const vi = varuint$1.decode(this.buffer, this.offset);
    this.offset += varuint$1.decode.bytes;
    return vi;
  }
  readSlice(n) {
    if (this.buffer.length < this.offset + n) {
      throw new Error('Cannot read slice out of bounds');
    }
    const result = this.buffer.slice(this.offset, this.offset + n);
    this.offset += n;
    return result;
  }
  readVarSlice() {
    return this.readSlice(this.readVarInt());
  }
  readVector() {
    const count = this.readVarInt();
    const vector = [];
    for (let i = 0; i < count; i++) vector.push(this.readVarSlice());
    return vector;
  }
  // CConfidentialAsset size 33, prefixA 10, prefixB 11
  readConfidentialAsset() {
    const version = this.readUInt8();
    const versionBuffer = this.buffer.slice(this.offset - 1, this.offset);
    if (version === 1 || version === 0xff)
      return Buffer$1.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_COMMITMENT - 1),
      ]);
    else if (version === 10 || version === 11)
      return Buffer$1.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_COMMITMENT - 1),
      ]);
    return versionBuffer;
  }
  // CConfidentialNonce size 33, prefixA 2, prefixB 3
  readConfidentialNonce() {
    const version = this.readUInt8();
    const versionBuffer = this.buffer.slice(this.offset - 1, this.offset);
    if (version === 1 || version === 0xff)
      return Buffer$1.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_COMMITMENT - 1),
      ]);
    else if (version === 2 || version === 3)
      return Buffer$1.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_COMMITMENT - 1),
      ]);
    return versionBuffer;
  }
  // CConfidentialValue size 9, prefixA 8, prefixB 9
  readConfidentialValue() {
    const version = this.readUInt8();
    const versionBuffer = this.buffer.slice(this.offset - 1, this.offset);
    if (version === 1 || version === 0xff)
      return Buffer$1.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_VALUE$1 - 1),
      ]);
    else if (version === 8 || version === 9)
      return Buffer$1.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_COMMITMENT - 1),
      ]);
    return versionBuffer;
  }
  readConfidentialInFields() {
    const issuanceRangeProof = this.readVarSlice();
    const inflationRangeProof = this.readVarSlice();
    const witness = this.readVector();
    const peginWitness = this.readVector();
    return {
      issuanceRangeProof,
      inflationRangeProof,
      witness,
      peginWitness,
    };
  }
  readConfidentialOutFields() {
    const surjectionProof = this.readVarSlice();
    const rangeProof = this.readVarSlice();
    return { surjectionProof, rangeProof };
  }
  readIssuance() {
    const issuanceNonce = this.readSlice(32);
    const issuanceEntropy = this.readSlice(32);
    const amount = this.readConfidentialValue();
    const inflation = this.readConfidentialValue();
    return {
      assetBlindingNonce: issuanceNonce,
      assetEntropy: issuanceEntropy,
      assetAmount: amount,
      tokenAmount: inflation,
    };
  }
}
var BufferReader_1 = BufferReader;

var bufferutils$1 = /*#__PURE__*/Object.defineProperty({
	readUInt64LE: readUInt64LE_1,
	writeUInt64LE: writeUInt64LE_1,
	reverseBuffer: reverseBuffer_1,
	BufferWriter: BufferWriter_1,
	BufferReader: BufferReader_1
}, '__esModule', {value: true});

var __awaiter$1 =
  (commonjsGlobal && commonjsGlobal.__awaiter) ||
  function(thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function(resolve, reject) {
      function fulfilled(value) {
        try {
          step(generator.next(value));
        } catch (e) {
          reject(e);
        }
      }
      function rejected(value) {
        try {
          step(generator['throw'](value));
        } catch (e) {
          reject(e);
        }
      }
      function step(result) {
        result.done
          ? resolve(result.value)
          : new P(function(resolve) {
              resolve(result.value);
            }).then(fulfilled, rejected);
      }
      step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
  };
var __importStar$5 =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };
var __importDefault =
  (commonjsGlobal && commonjsGlobal.__importDefault) ||
  function(mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };

const bufferutils = __importStar$5(bufferutils$1);
const crypto$1 = __importStar$5(crypto$2);
const secp256k1_zkp_1 = __importDefault(require$$2);
const secp256k1Promise = secp256k1_zkp_1.default();
function nonceHash(pubkey, privkey) {
  return __awaiter$1(this, void 0, void 0, function*() {
    const { ecdh } = yield secp256k1Promise;
    return crypto$1.sha256(ecdh(pubkey, privkey));
  });
}
function valueBlindingFactor(
  inValues,
  outValues,
  inGenerators,
  outGenerators,
  inFactors,
  outFactors,
) {
  return __awaiter$1(this, void 0, void 0, function*() {
    const { pedersen } = yield secp256k1Promise;
    const values = inValues.concat(outValues);
    const nInputs = inValues.length;
    const generators = inGenerators.concat(outGenerators);
    const factors = inFactors.concat(outFactors);
    return pedersen.blindGeneratorBlindSum(
      values,
      nInputs,
      generators,
      factors,
    );
  });
}
var valueBlindingFactor_1 = valueBlindingFactor;
function valueCommitment(value, gen, factor) {
  return __awaiter$1(this, void 0, void 0, function*() {
    const { generator, pedersen } = yield secp256k1Promise;
    const generatorParsed = generator.parse(gen);
    const commit = pedersen.commit(factor, value, generatorParsed);
    return pedersen.commitSerialize(commit);
  });
}
var valueCommitment_1 = valueCommitment;
function assetCommitment(asset, factor) {
  return __awaiter$1(this, void 0, void 0, function*() {
    const { generator } = yield secp256k1Promise;
    const gen = generator.generateBlinded(asset, factor);
    return generator.serialize(gen);
  });
}
var assetCommitment_1 = assetCommitment;
function unblindOutputWithKey(out, blindingPrivKey) {
  return __awaiter$1(this, void 0, void 0, function*() {
    const nonce = yield nonceHash(out.nonce, blindingPrivKey);
    return unblindOutputWithNonce(out, nonce);
  });
}
var unblindOutputWithKey_1 = unblindOutputWithKey;
function unblindOutputWithNonce(out, nonce) {
  return __awaiter$1(this, void 0, void 0, function*() {
    const secp = yield secp256k1Promise;
    const gen = secp.generator.parse(out.asset);
    const { value, blindFactor, message } = secp.rangeproof.rewind(
      out.value,
      out.rangeProof,
      nonce,
      gen,
      out.script,
    );
    return {
      value,
      asset: message.slice(0, 32),
      valueBlindingFactor: blindFactor,
      assetBlindingFactor: message.slice(32),
    };
  });
}
var unblindOutputWithNonce_1 = unblindOutputWithNonce;
function rangeProofInfo(proof) {
  return __awaiter$1(this, void 0, void 0, function*() {
    const { rangeproof } = yield secp256k1Promise;
    const { exp, mantissa, minValue, maxValue } = rangeproof.info(proof);
    return {
      minValue: parseInt(minValue, 10),
      maxValue: parseInt(maxValue, 10),
      ctExp: exp,
      ctBits: parseInt(mantissa, 10),
    };
  });
}
var rangeProofInfo_1 = rangeProofInfo;
function rangeProof(
  value,
  blindingPubkey,
  ephemeralPrivkey,
  asset,
  assetBlindingFactor,
  valueBlindFactor,
  valueCommit,
  scriptPubkey,
  minValue,
  exp,
  minBits,
) {
  return __awaiter$1(this, void 0, void 0, function*() {
    const nonce = yield nonceHash(blindingPubkey, ephemeralPrivkey);
    return rangeProofWithoutNonceHash(
      value,
      nonce,
      asset,
      assetBlindingFactor,
      valueBlindFactor,
      valueCommit,
      scriptPubkey,
      minValue,
      exp,
      minBits,
    );
  });
}
var rangeProof_1 = rangeProof;
function rangeProofWithoutNonceHash(
  value,
  nonce,
  asset,
  assetBlindingFactor,
  valueBlindFactor,
  valueCommit,
  scriptPubkey,
  minValue,
  exp,
  minBits,
) {
  return __awaiter$1(this, void 0, void 0, function*() {
    const { generator, pedersen, rangeproof } = yield secp256k1Promise;
    const gen = generator.generateBlinded(asset, assetBlindingFactor);
    const message = Buffer$1.concat([asset, assetBlindingFactor]);
    const commit = pedersen.commitParse(valueCommit);
    const mv = minValue ? minValue : '1';
    const e = exp ? exp : 0;
    const mb = minBits ? minBits : 36;
    return rangeproof.sign(
      commit,
      valueBlindFactor,
      nonce,
      value,
      gen,
      mv,
      e,
      mb,
      message,
      scriptPubkey,
    );
  });
}
var rangeProofWithoutNonceHash_1 = rangeProofWithoutNonceHash;
function surjectionProof(
  outputAsset,
  outputAssetBlindingFactor,
  inputAssets,
  inputAssetBlindingFactors,
  seed,
) {
  return __awaiter$1(this, void 0, void 0, function*() {
    const { generator, surjectionproof } = yield secp256k1Promise;
    const outputGenerator = generator.generateBlinded(
      outputAsset,
      outputAssetBlindingFactor,
    );
    const inputGenerators = inputAssets.map((v, i) =>
      generator.generateBlinded(v, inputAssetBlindingFactors[i]),
    );
    const nInputsToUse = inputAssets.length > 3 ? 3 : inputAssets.length;
    const maxIterations = 100;
    const init = surjectionproof.initialize(
      inputAssets,
      nInputsToUse,
      outputAsset,
      maxIterations,
      seed,
    );
    const proof = surjectionproof.generate(
      init.proof,
      inputGenerators,
      outputGenerator,
      init.inputIndex,
      inputAssetBlindingFactors[init.inputIndex],
      outputAssetBlindingFactor,
    );
    return surjectionproof.serialize(proof);
  });
}
var surjectionProof_1 = surjectionProof;
const CONFIDENTIAL_VALUE = 9; // explicit size of confidential values
function confidentialValueToSatoshi(value) {
  if (!isUnconfidentialValue(value)) {
    throw new Error(
      'Value must be unconfidential, length or the prefix are not valid',
    );
  }
  const reverseValueBuffer = Buffer$1.allocUnsafe(CONFIDENTIAL_VALUE - 1);
  value.slice(1, CONFIDENTIAL_VALUE).copy(reverseValueBuffer, 0);
  bufferutils.reverseBuffer(reverseValueBuffer);
  return bufferutils.readUInt64LE(reverseValueBuffer, 0);
}
var confidentialValueToSatoshi_1 = confidentialValueToSatoshi;
function satoshiToConfidentialValue(amount) {
  const unconfPrefix = Buffer$1.allocUnsafe(1);
  const valueBuffer = Buffer$1.allocUnsafe(CONFIDENTIAL_VALUE - 1);
  unconfPrefix.writeUInt8(1, 0);
  bufferutils.writeUInt64LE(valueBuffer, amount, 0);
  return Buffer$1.concat([unconfPrefix, bufferutils.reverseBuffer(valueBuffer)]);
}
var satoshiToConfidentialValue_1 = satoshiToConfidentialValue;
function isUnconfidentialValue(value) {
  return value.length === CONFIDENTIAL_VALUE && value.readUInt8(0) === 1;
}
var isUnconfidentialValue_1 = isUnconfidentialValue;

var confidential$2 = /*#__PURE__*/Object.defineProperty({
	valueBlindingFactor: valueBlindingFactor_1,
	valueCommitment: valueCommitment_1,
	assetCommitment: assetCommitment_1,
	unblindOutputWithKey: unblindOutputWithKey_1,
	unblindOutputWithNonce: unblindOutputWithNonce_1,
	rangeProofInfo: rangeProofInfo_1,
	rangeProof: rangeProof_1,
	rangeProofWithoutNonceHash: rangeProofWithoutNonceHash_1,
	surjectionProof: surjectionProof_1,
	confidentialValueToSatoshi: confidentialValueToSatoshi_1,
	satoshiToConfidentialValue: satoshiToConfidentialValue_1,
	isUnconfidentialValue: isUnconfidentialValue_1
}, '__esModule', {value: true});

var __importStar$4 =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };

const NETWORKS = __importStar$4(networks$2);
const types$1 = __importStar$4(types$5);




const isOptions = typef.maybe(
  typef.compile({
    compressed: types$1.maybe(types$1.Boolean),
    network: types$1.maybe(types$1.Network),
  }),
);
class ECPair$1 {
  constructor(__D, __Q, options) {
    this.__D = __D;
    this.__Q = __Q;
    this.lowR = false;
    if (options === undefined) options = {};
    this.compressed =
      options.compressed === undefined ? true : options.compressed;
    this.network = options.network || NETWORKS.liquid;
    if (__Q !== undefined) this.__Q = ecc.pointCompress(__Q, this.compressed);
  }
  get privateKey() {
    return this.__D;
  }
  get publicKey() {
    if (!this.__Q) this.__Q = ecc.pointFromScalar(this.__D, this.compressed);
    return this.__Q;
  }
  toWIF() {
    if (!this.__D) throw new Error('Missing private key');
    return wif.encode(this.network.wif, this.__D, this.compressed);
  }
  sign(hash, lowR) {
    if (!this.__D) throw new Error('Missing private key');
    if (lowR === undefined) lowR = this.lowR;
    if (lowR === false) {
      return ecc.sign(hash, this.__D);
    } else {
      let sig = ecc.sign(hash, this.__D);
      const extraData = Buffer$1.alloc(32, 0);
      let counter = 0;
      // if first try is lowR, skip the loop
      // for second try and on, add extra entropy counting up
      while (sig[0] > 0x7f) {
        counter++;
        extraData.writeUIntLE(counter, 0, 6);
        sig = ecc.signWithEntropy(hash, this.__D, extraData);
      }
      return sig;
    }
  }
  verify(hash, signature) {
    return ecc.verify(hash, this.publicKey, signature);
  }
}
function fromPrivateKey(buffer, options) {
  typef(types$1.Buffer256bit, buffer);
  if (!ecc.isPrivate(buffer))
    throw new TypeError('Private key not in range [1, n)');
  typef(isOptions, options);
  return new ECPair$1(buffer, undefined, options);
}
var fromPrivateKey_1 = fromPrivateKey;
function fromPublicKey(buffer, options) {
  typef(ecc.isPoint, buffer);
  typef(isOptions, options);
  return new ECPair$1(undefined, buffer, options);
}
var fromPublicKey_1 = fromPublicKey;
function fromWIF(wifString, network) {
  const decoded = wif.decode(wifString);
  const version = decoded.version;
  // list of networks?
  if (types$1.Array(network)) {
    network = network
      .filter(x => {
        return version === x.wif;
      })
      .pop();
    if (!network) throw new Error('Unknown network version');
    // otherwise, assume a network object (or default to bitcoin)
  } else {
    network = network || NETWORKS.liquid;
    if (version !== network.wif) throw new Error('Invalid network version');
  }
  return fromPrivateKey(decoded.privateKey, {
    compressed: decoded.compressed,
    network: network,
  });
}
var fromWIF_1 = fromWIF;
function makeRandom(options) {
  typef(isOptions, options);
  if (options === undefined) options = {};
  const rng = options.rng || randomBytes$1;
  let d;
  do {
    d = rng(32);
    typef(types$1.Buffer256bit, d);
  } while (!ecc.isPrivate(d));
  return fromPrivateKey(d, options);
}
var makeRandom_1 = makeRandom;

var ecpair = /*#__PURE__*/Object.defineProperty({
	fromPrivateKey: fromPrivateKey_1,
	fromPublicKey: fromPublicKey_1,
	fromWIF: fromWIF_1,
	makeRandom: makeRandom_1
}, '__esModule', {value: true});

var transaction = createCommonjsModule(function (module, exports) {
var __importStar =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });

const bcrypto = __importStar(crypto$2);
const bscript = __importStar(script$1);

const types = __importStar(types$5);


function varSliceSize(someScript) {
  const length = someScript.length;
  return varuint$1.encodingLength(length) + length;
}
const EMPTY_SCRIPT = Buffer$1.allocUnsafe(0);
const EMPTY_WITNESS = [];
exports.ZERO = Buffer$1.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
);
const ONE = Buffer$1.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);
const WITNESS_SCALE_FACTOR = 4;
const OUTPOINT_ISSUANCE_FLAG = (1 << 31) >>> 0;
const OUTPOINT_PEGIN_FLAG = (1 << 30) >>> 0;
const OUTPOINT_INDEX_MASK = 0x3fffffff;
const MINUS_1 = 4294967295;
const VALUE_UINT64_MAX = Buffer$1.from('ffffffffffffffff', 'hex');
const BLANK_OUTPUT = {
  script: EMPTY_SCRIPT,
  asset: exports.ZERO,
  nonce: exports.ZERO,
  value: VALUE_UINT64_MAX,
};
class Transaction {
  constructor() {
    this.version = 1;
    this.locktime = 0;
    this.flag = 0;
    this.ins = [];
    this.outs = [];
  }
  static fromBuffer(buffer, _NO_STRICT) {
    const bufferReader = new bufferutils$1.BufferReader(buffer);
    const tx = new Transaction();
    tx.version = bufferReader.readInt32();
    tx.flag = bufferReader.readUInt8();
    const vinLen = bufferReader.readVarInt();
    for (let i = 0; i < vinLen; ++i) {
      const inHash = bufferReader.readSlice(32);
      let inIndex = bufferReader.readUInt32();
      const inScript = bufferReader.readVarSlice();
      const inSequence = bufferReader.readUInt32();
      let inIsPegin = false;
      let inIssuance;
      if (inIndex !== MINUS_1) {
        if (inIndex & OUTPOINT_ISSUANCE_FLAG) {
          inIssuance = bufferReader.readIssuance();
        }
        if (inIndex & OUTPOINT_PEGIN_FLAG) {
          inIsPegin = true;
        }
        inIndex &= OUTPOINT_INDEX_MASK;
      }
      tx.ins.push({
        hash: inHash,
        index: inIndex,
        script: inScript,
        sequence: inSequence,
        witness: EMPTY_WITNESS,
        isPegin: inIsPegin,
        issuance: inIssuance,
        peginWitness: EMPTY_WITNESS,
        issuanceRangeProof: EMPTY_SCRIPT,
        inflationRangeProof: EMPTY_SCRIPT,
      });
    }
    const voutLen = bufferReader.readVarInt();
    for (let i = 0; i < voutLen; ++i) {
      const asset = bufferReader.readConfidentialAsset();
      const value = bufferReader.readConfidentialValue();
      const nonce = bufferReader.readConfidentialNonce();
      const script = bufferReader.readVarSlice();
      tx.outs.push({
        asset,
        value,
        nonce,
        script,
        rangeProof: EMPTY_SCRIPT,
        surjectionProof: EMPTY_SCRIPT,
      });
    }
    tx.locktime = bufferReader.readUInt32();
    if (tx.flag === 1) {
      for (let i = 0; i < vinLen; ++i) {
        const {
          witness,
          peginWitness,
          issuanceRangeProof,
          inflationRangeProof,
        } = bufferReader.readConfidentialInFields();
        tx.ins[i].witness = witness;
        tx.ins[i].peginWitness = peginWitness;
        tx.ins[i].issuanceRangeProof = issuanceRangeProof;
        tx.ins[i].inflationRangeProof = inflationRangeProof;
      }
      for (let i = 0; i < voutLen; ++i) {
        const {
          rangeProof,
          surjectionProof,
        } = bufferReader.readConfidentialOutFields();
        tx.outs[i].rangeProof = rangeProof;
        tx.outs[i].surjectionProof = surjectionProof;
      }
    }
    if (_NO_STRICT) return tx;
    if (bufferReader.offset !== buffer.length)
      throw new Error('Transaction has unexpected data');
    return tx;
  }
  static fromHex(hex) {
    return Transaction.fromBuffer(Buffer$1.from(hex, 'hex'), false);
  }
  static isCoinbaseHash(buffer) {
    typef(types.Hash256bit, buffer);
    for (let i = 0; i < 32; ++i) {
      if (buffer[i] !== 0) return false;
    }
    return true;
  }
  isCoinbase() {
    return (
      this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash)
    );
  }
  // A quick and reliable way to validate that all the buffers are of correct type and length
  validateIssuance(assetBlindingNonce, assetEntropy, assetAmount, tokenAmount) {
    typef(types.Hash256bit, assetBlindingNonce);
    typef(types.Hash256bit, assetEntropy);
    typef(
      types.oneOf(
        types.ConfidentialValue,
        types.ConfidentialCommitment,
        types.BufferOne,
      ),
      assetAmount,
    );
    typef(
      types.oneOf(
        types.ConfidentialValue,
        types.ConfidentialCommitment,
        types.BufferOne,
      ),
      tokenAmount,
    );
    return true;
  }
  addInput(hash, index, sequence, scriptSig, issuance) {
    typef(
      types.tuple(
        types.Hash256bit,
        types.UInt32,
        types.maybe(types.UInt32),
        types.maybe(types.Buffer),
        types.maybe(types.Object),
      ),
      arguments,
    );
    let isPegin = false;
    if (index !== MINUS_1) {
      if (index & OUTPOINT_ISSUANCE_FLAG) {
        if (!issuance) {
          throw new Error(
            'Issuance flag has been set but the Issuance object is not defined or invalid',
          );
        } else
          this.validateIssuance(
            issuance.assetBlindingNonce,
            issuance.assetEntropy,
            issuance.assetAmount,
            issuance.tokenAmount,
          );
      }
      if (index & OUTPOINT_PEGIN_FLAG) {
        isPegin = true;
      }
      index &= OUTPOINT_INDEX_MASK;
    }
    // Add the input and return the input's index
    return (
      this.ins.push({
        hash,
        index,
        isPegin,
        issuance,
        witness: EMPTY_WITNESS,
        peginWitness: EMPTY_WITNESS,
        issuanceRangeProof: EMPTY_SCRIPT,
        inflationRangeProof: EMPTY_SCRIPT,
        script: scriptSig || EMPTY_SCRIPT,
        sequence: sequence || Transaction.DEFAULT_SEQUENCE,
      }) - 1
    );
  }
  addOutput(scriptPubKey, value, asset, nonce, rangeProof, surjectionProof) {
    /*
        typeforce(
          types.tuple(
            types.Buffer,
            types.oneOf(
              types.ConfidentialValue,
              types.ConfidentialCommitment,
              types.BufferOne,
            ),
            types.oneOf(types.ConfidentialCommitment, types.BufferOne),
            types.oneOf(types.ConfidentialCommitment, types.BufferOne),
            types.maybe(types.Buffer),
            types.maybe(types.Buffer),
          ),
          arguments,
        );
        */
    // Add the output and return the output's index
    return (
      this.outs.push({
        script: scriptPubKey,
        value,
        asset,
        nonce,
        rangeProof: rangeProof || EMPTY_SCRIPT,
        surjectionProof: surjectionProof || EMPTY_SCRIPT,
      }) - 1
    );
  }
  hasWitnesses() {
    return (
      this.flag === 1 ||
      this.ins.some(x => {
        return x.witness.length !== 0;
      }) ||
      this.outs.some(x => {
        return x.rangeProof.length !== 0 && x.surjectionProof.length !== 0;
      })
    );
  }
  weight() {
    const base = this.__byteLength(false);
    const total = this.__byteLength(true);
    return base * (WITNESS_SCALE_FACTOR - 1) + total;
  }
  virtualSize() {
    const vsize =
      (this.weight() + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    return Math.floor(vsize);
  }
  byteLength(_ALLOW_WITNESS) {
    return this.__byteLength(_ALLOW_WITNESS || true);
  }
  clone() {
    const newTx = new Transaction();
    newTx.version = this.version;
    newTx.locktime = this.locktime;
    newTx.flag = this.flag;
    newTx.ins = this.ins.map(txIn => {
      return {
        hash: txIn.hash,
        index: txIn.index,
        script: txIn.script,
        sequence: txIn.sequence,
        witness: txIn.witness,
        isPegin: txIn.isPegin,
        issuance: txIn.issuance,
        peginWitness: txIn.peginWitness,
        issuanceRangeProof: txIn.issuanceRangeProof,
        inflationRangeProof: txIn.inflationRangeProof,
      };
    });
    newTx.outs = this.outs.map(txOut => {
      return {
        script: txOut.script,
        value: txOut.value,
        asset: txOut.asset,
        nonce: txOut.nonce,
        rangeProof: txOut.rangeProof,
        surjectionProof: txOut.surjectionProof,
      };
    });
    return newTx;
  }
  /**
   * Hash transaction for signing a specific input.
   *
   * Bitcoin uses a different hash for each signed transaction input.
   * This method copies the transaction, makes the necessary changes based on the
   * hashType, and then hashes the result.
   * This hash can then be used to sign the provided transaction input.
   */
  hashForSignature(inIndex, prevOutScript, hashType) {
    typef(
      types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number),
      arguments,
    );
    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
    if (inIndex >= this.ins.length) return ONE;
    // ignore OP_CODESEPARATOR
    const ourScript = bscript.compile(
      bscript.decompile(prevOutScript).filter(x => {
        return x !== script$1.OPS.OP_CODESEPARATOR;
      }),
    );
    const txTmp = this.clone();
    // SIGHASH_NONE: ignore all outputs? (wildcard payee)
    if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
      txTmp.outs = [];
      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, i) => {
        if (i === inIndex) return;
        input.sequence = 0;
      });
      // SIGHASH_SINGLE: ignore all outputs, except at the same index?
    } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
      // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
      if (inIndex >= this.outs.length) return ONE;
      // truncate outputs after
      txTmp.outs.length = inIndex + 1;
      // "blank" outputs before
      for (let i = 0; i < inIndex; i++) {
        txTmp.outs[i] = BLANK_OUTPUT;
      }
      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, y) => {
        if (y === inIndex) return;
        input.sequence = 0;
      });
    }
    // SIGHASH_ANYONECANPAY: ignore inputs entirely?
    if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
      txTmp.ins = [txTmp.ins[inIndex]];
      txTmp.ins[0].script = ourScript;
      // SIGHASH_ALL: only ignore input scripts
    } else {
      // "blank" others input scripts
      txTmp.ins.forEach(input => {
        input.script = EMPTY_SCRIPT;
      });
      txTmp.ins[inIndex].script = ourScript;
    }
    // serialize and hash
    const buffer = Buffer$1.allocUnsafe(txTmp.__byteLength(false, true) + 4);
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0, false, true, true);
    return bcrypto.hash256(buffer);
  }
  hashForWitnessV0(inIndex, prevOutScript, value, hashType) {
    typef(
      types.tuple(types.UInt32, types.Buffer, types.Buffer, types.UInt32),
      arguments,
    );
    function writeInputs(ins) {
      const tBuffer = Buffer$1.allocUnsafe(36 * ins.length);
      const tBufferWriter = new bufferutils$1.BufferWriter(tBuffer, 0);
      ins.forEach(txIn => {
        tBufferWriter.writeSlice(txIn.hash);
        tBufferWriter.writeUInt32(txIn.index);
      });
      return bcrypto.hash256(tBuffer);
    }
    function writeSequences(ins) {
      const tBuffer = Buffer$1.allocUnsafe(4 * ins.length);
      const tBufferWriter = new bufferutils$1.BufferWriter(tBuffer, 0);
      ins.forEach(txIn => {
        tBufferWriter.writeUInt32(txIn.sequence);
      });
      return bcrypto.hash256(tBuffer);
    }
    function issuanceSize(ins) {
      return ins.reduce(
        (sum, txIn) =>
          !types.Null(txIn.issuance)
            ? sum +
              txIn.issuance.assetBlindingNonce.length +
              txIn.issuance.assetEntropy.length +
              txIn.issuance.assetAmount.length +
              txIn.issuance.tokenAmount.length
            : sum, // we'll use the empty 00 Buffer if issuance is not set
        0,
      );
    }
    function writeIssuances(ins, sizeIssuances) {
      const size = sizeIssuances === 0 ? ins.length : sizeIssuances;
      const tBuffer = Buffer$1.allocUnsafe(size);
      const tBufferWriter = new bufferutils$1.BufferWriter(tBuffer, 0);
      ins.forEach(txIn => {
        if (!types.Null(txIn.issuance)) {
          tBufferWriter.writeSlice(txIn.issuance.assetBlindingNonce);
          tBufferWriter.writeSlice(txIn.issuance.assetEntropy);
          tBufferWriter.writeSlice(txIn.issuance.assetAmount);
          tBufferWriter.writeSlice(txIn.issuance.tokenAmount);
        } else {
          tBufferWriter.writeSlice(Buffer$1.from('00', 'hex'));
        }
      });
      return bcrypto.hash256(tBuffer);
    }
    function writeOutputs(outs) {
      const outsSize = outs.reduce(
        (sum, txOut) =>
          sum +
          txOut.asset.length +
          txOut.value.length +
          txOut.nonce.length +
          varSliceSize(txOut.script),
        0,
      );
      const tBuffer = Buffer$1.allocUnsafe(outsSize);
      const tBufferWriter = new bufferutils$1.BufferWriter(tBuffer, 0);
      outs.forEach(txOut => {
        tBufferWriter.writeSlice(txOut.asset);
        tBufferWriter.writeSlice(txOut.value);
        tBufferWriter.writeSlice(txOut.nonce);
        tBufferWriter.writeVarSlice(txOut.script);
      });
      return bcrypto.hash256(tBuffer);
    }
    let hashOutputs = exports.ZERO;
    let hashPrevouts = exports.ZERO;
    let hashSequences = exports.ZERO;
    let hashIssuances = exports.ZERO;
    let sizeOfIssuances = 0;
    // Inputs
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      hashPrevouts = writeInputs(this.ins);
    }
    // Sequences
    if (
      !(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      hashSequences = writeSequences(this.ins);
    }
    // Issuances
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      sizeOfIssuances = issuanceSize(this.ins);
      hashIssuances = writeIssuances(this.ins, sizeOfIssuances);
    }
    // Outputs
    if (
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      hashOutputs = writeOutputs(this.outs);
    } else if (
      (hashType & 0x1f) === Transaction.SIGHASH_SINGLE &&
      inIndex < this.outs.length
    ) {
      hashOutputs = writeOutputs([this.outs[inIndex]]);
    }
    const input = this.ins[inIndex];
    const hasIssuance = !types.Null(input.issuance);
    const bufferSize =
      4 + // version
      hashPrevouts.length +
      hashSequences.length +
      hashIssuances.length +
      input.hash.length +
      4 + // input.index
      varSliceSize(prevOutScript) +
      value.length +
      4 + // input.sequence
      hashOutputs.length +
      sizeOfIssuances +
      4 + // locktime
      4; // hashType
    const buffer = Buffer$1.allocUnsafe(bufferSize);
    const bufferWriter = new bufferutils$1.BufferWriter(buffer, 0);
    bufferWriter.writeUInt32(this.version);
    bufferWriter.writeSlice(hashPrevouts);
    bufferWriter.writeSlice(hashSequences);
    bufferWriter.writeSlice(hashIssuances);
    bufferWriter.writeSlice(input.hash);
    bufferWriter.writeUInt32(input.index);
    bufferWriter.writeVarSlice(prevOutScript);
    bufferWriter.writeSlice(value);
    bufferWriter.writeUInt32(input.sequence);
    if (hasIssuance) {
      bufferWriter.writeSlice(input.issuance.assetBlindingNonce);
      bufferWriter.writeSlice(input.issuance.assetEntropy);
      bufferWriter.writeSlice(input.issuance.assetAmount);
      bufferWriter.writeSlice(input.issuance.tokenAmount);
    }
    bufferWriter.writeSlice(hashOutputs);
    bufferWriter.writeUInt32(this.locktime);
    bufferWriter.writeUInt32(hashType);
    return bcrypto.hash256(buffer);
  }
  getHash(forWitness) {
    // wtxid for coinbase is always 32 bytes of 0x00
    if (forWitness && this.isCoinbase()) return Buffer$1.alloc(32, 0);
    return bcrypto.hash256(
      this.__toBuffer(undefined, undefined, forWitness, true),
    );
  }
  getId() {
    // transaction hash's are displayed in reverse order
    return bufferutils$1.reverseBuffer(this.getHash(false)).toString('hex');
  }
  toBuffer(buffer, initialOffset) {
    return this.__toBuffer(buffer, initialOffset, true);
  }
  toHex() {
    return this.toBuffer(undefined, undefined).toString('hex');
  }
  setInputScript(index, scriptSig) {
    typef(types.tuple(types.Number, types.Buffer), arguments);
    this.ins[index].script = scriptSig;
  }
  setWitness(index, witness) {
    typef(types.tuple(types.Number, [types.Buffer]), arguments);
    this.ins[index].witness = witness;
  }
  setPeginWitness(index, peginWitness) {
    typef(types.tuple(types.Number, [types.Buffer]), arguments);
    this.ins[index].peginWitness = peginWitness;
  }
  setInputIssuanceRangeProof(index, issuanceRangeProof) {
    typef(types.tuple(types.Buffer), arguments);
    if (this.ins[index].issuance === undefined)
      throw new Error('Issuance not set for input #' + index);
    this.ins[index].issuanceRangeProof = issuanceRangeProof;
  }
  setInputInflationRangeProof(index, inflationRangeProof) {
    typef(types.tuple(types.Buffer), arguments);
    if (this.ins[index].issuance === undefined)
      throw new Error('Issuance not set for input #' + index);
    this.ins[index].inflationRangeProof = inflationRangeProof;
  }
  setOutputNonce(index, nonce) {
    typef(types.tuple(types.Number, types.Buffer), arguments);
    this.outs[index].nonce = nonce;
  }
  setOutputRangeProof(index, proof) {
    typef(types.tuple(types.Number, types.Buffer), arguments);
    this.outs[index].rangeProof = proof;
  }
  setOutputSurjectionProof(index, proof) {
    typef(types.tuple(types.Number, types.Buffer), arguments);
    this.outs[index].surjectionProof = proof;
  }
  __byteLength(_ALLOW_WITNESS, forSignature) {
    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    return (
      8 +
      (forSignature ? 0 : 1) +
      varuint$1.encodingLength(this.ins.length) +
      varuint$1.encodingLength(this.outs.length) +
      this.ins.reduce((sum, input) => {
        return (
          sum +
          40 +
          varSliceSize(input.script) +
          (input.issuance
            ? 64 +
              input.issuance.assetAmount.length +
              input.issuance.tokenAmount.length
            : 0)
        );
      }, 0) +
      this.outs.reduce((sum, output) => {
        return (
          sum +
          output.asset.length +
          output.value.length +
          output.nonce.length +
          varSliceSize(output.script)
        );
      }, 0) +
      (hasWitnesses
        ? this.ins.reduce((sum, input) => {
            return (
              sum +
              varSliceSize(input.issuanceRangeProof) +
              varSliceSize(input.inflationRangeProof) +
              varuint$1.encodingLength(input.witness.length) +
              input.witness.reduce((scriptSum, scriptWit) => {
                return scriptSum + varSliceSize(scriptWit);
              }, 0) +
              varuint$1.encodingLength(input.peginWitness.length) +
              input.peginWitness.reduce((peginSum, peginWit) => {
                return peginSum + varSliceSize(peginWit);
              }, 0)
            );
          }, 0)
        : 0) +
      (hasWitnesses
        ? this.outs.reduce((sum, output) => {
            return (
              sum +
              varSliceSize(output.surjectionProof) +
              varSliceSize(output.rangeProof)
            );
          }, 0)
        : 0)
    );
  }
  __toBuffer(
    buffer,
    initialOffset,
    _ALLOW_WITNESS,
    forceZeroFlag,
    forSignature,
  ) {
    if (!buffer)
      buffer = Buffer$1.allocUnsafe(
        this.__byteLength(_ALLOW_WITNESS, forSignature),
      );
    const bufferWriter = new bufferutils$1.BufferWriter(
      buffer,
      initialOffset || 0,
    );
    bufferWriter.writeInt32(this.version);
    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    if (!forSignature) {
      if (
        hasWitnesses &&
        (forceZeroFlag === false || forceZeroFlag === undefined)
      )
        bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG);
      else bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER);
    }
    bufferWriter.writeVarInt(this.ins.length);
    this.ins.forEach(txIn => {
      bufferWriter.writeSlice(txIn.hash);
      let prevIndex = txIn.index;
      if (txIn.issuance) {
        prevIndex = (prevIndex | OUTPOINT_ISSUANCE_FLAG) >>> 0;
      }
      if (txIn.isPegin) {
        prevIndex = (prevIndex | OUTPOINT_PEGIN_FLAG) >>> 0;
      }
      bufferWriter.writeUInt32(prevIndex);
      bufferWriter.writeVarSlice(txIn.script);
      bufferWriter.writeUInt32(txIn.sequence);
      if (txIn.issuance) {
        bufferWriter.writeSlice(txIn.issuance.assetBlindingNonce);
        bufferWriter.writeSlice(txIn.issuance.assetEntropy);
        bufferWriter.writeSlice(txIn.issuance.assetAmount);
        bufferWriter.writeSlice(txIn.issuance.tokenAmount);
      }
    });
    bufferWriter.writeVarInt(this.outs.length);
    this.outs.forEach(txOut => {
      // if we are serializing a confidential output for producing a signature,
      // we must exclude the confidential value from the serialization and
      // use the satoshi 0 value instead, as done for typical bitcoin witness signatures.
      const val = forSignature && hasWitnesses ? Buffer$1.alloc(0) : txOut.value;
      bufferWriter.writeSlice(txOut.asset);
      bufferWriter.writeSlice(val);
      bufferWriter.writeSlice(txOut.nonce);
      if (forSignature && hasWitnesses) bufferWriter.writeUInt64(0);
      bufferWriter.writeVarSlice(txOut.script);
    });
    bufferWriter.writeUInt32(this.locktime);
    if (!forSignature && hasWitnesses) {
      this.ins.forEach(input => {
        bufferWriter.writeConfidentialInFields(input);
      });
      this.outs.forEach(output => {
        bufferWriter.writeConfidentialOutFields(output);
      });
    }
    // avoid slicing unless necessary
    if (initialOffset !== undefined)
      return buffer.slice(initialOffset, bufferWriter.offset);
    return buffer;
  }
}
Transaction.DEFAULT_SEQUENCE = 0xffffffff;
Transaction.SIGHASH_ALL = 0x01;
Transaction.SIGHASH_NONE = 0x02;
Transaction.SIGHASH_SINGLE = 0x03;
Transaction.SIGHASH_ANYONECANPAY = 0x80;
Transaction.ADVANCED_TRANSACTION_MARKER = 0x00;
Transaction.ADVANCED_TRANSACTION_FLAG = 0x01;
exports.Transaction = Transaction;
});

var __importStar$3 =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };


const bcrypto$1 = __importStar$3(crypto$2);

const types = __importStar$3(types$5);



const errorMerkleNoTxes = new TypeError(
  'Cannot compute merkle root for zero transactions',
);
const errorWitnessNotSegwit = new TypeError(
  'Cannot compute witness commit for non-segwit block',
);
class Block$1 {
  constructor() {
    this.version = 1;
    this.prevHash = undefined;
    this.merkleRoot = undefined;
    this.timestamp = 0;
    this.height = 0;
    this.witnessCommit = undefined;
    this.bits = 0;
    this.nonce = 0;
    this.transactions = undefined;
  }
  static fromBuffer(buffer, headersOnly = false) {
    if (buffer.length < 84) throw new Error('Buffer too small (< 84 bytes)');
    const bufferReader = new bufferutils$1.BufferReader(buffer);
    const block = new Block$1();
    block.version = bufferReader.readInt32();
    block.prevHash = bufferReader.readSlice(32);
    block.merkleRoot = bufferReader.readSlice(32);
    block.timestamp = bufferReader.readUInt32();
    block.height = bufferReader.readUInt32();
    block.bits = bufferReader.readUInt32();
    block.nonce = bufferReader.readUInt32();
    if (headersOnly || buffer.length === 84) return block;
    const readTransaction = () => {
      const tx = transaction.Transaction.fromBuffer(
        bufferReader.buffer.slice(bufferReader.offset),
        true,
      );
      bufferReader.offset += tx.byteLength();
      return tx;
    };
    const nTransactions = bufferReader.readVarInt();
    block.transactions = [];
    for (let i = 0; i < nTransactions; ++i) {
      const tx = readTransaction();
      block.transactions.push(tx);
    }
    const witnessCommit = block.getWitnessCommit();
    // This Block contains a witness commit
    if (witnessCommit) block.witnessCommit = witnessCommit;
    return block;
  }
  static fromHex(hex, headersOnly = false) {
    return Block$1.fromBuffer(Buffer$1.from(hex, 'hex'), headersOnly);
  }
  static calculateTarget(bits) {
    const exponent = ((bits & 0xff000000) >> 24) - 3;
    const mantissa = bits & 0x007fffff;
    const target = Buffer$1.alloc(32, 0);
    target.writeUIntBE(mantissa, 29 - exponent, 3);
    return target;
  }
  static calculateMerkleRoot(transactions, forWitness) {
    typef([{ getHash: types.Function }], transactions);
    if (transactions.length === 0) throw errorMerkleNoTxes;
    if (forWitness && !txesHaveWitnessCommit(transactions))
      throw errorWitnessNotSegwit;
    const hashes = transactions.map(transaction =>
      transaction.getHash(forWitness),
    );
    const rootHash = fastMerkleRoot(hashes, bcrypto$1.hash256);
    return forWitness
      ? bcrypto$1.hash256(
          Buffer$1.concat([rootHash, transactions[0].ins[0].witness[0]]),
        )
      : rootHash;
  }
  getWitnessCommit() {
    if (!txesHaveWitnessCommit(this.transactions)) return null;
    // The merkle root for the witness data is in an OP_RETURN output.
    // There is no rule for the index of the output, so use filter to find it.
    // The root is prepended with 0xaa21a9ed so check for 0x6a24aa21a9ed
    // If multiple commits are found, the output with highest index is assumed.
    const witnessCommits = this.transactions[0].outs
      .filter(out =>
        out.script.slice(0, 6).equals(Buffer$1.from('6a24aa21a9ed', 'hex')),
      )
      .map(out => out.script.slice(6, 38));
    if (witnessCommits.length === 0) return null;
    // Use the commit with the highest output (should only be one though)
    const result = witnessCommits[witnessCommits.length - 1];
    if (!(result instanceof Buffer$1 && result.length === 32)) return null;
    return result;
  }
  hasWitnessCommit() {
    if (
      this.witnessCommit instanceof Buffer$1 &&
      this.witnessCommit.length === 32
    )
      return true;
    if (this.getWitnessCommit() !== null) return true;
    return false;
  }
  hasWitness() {
    return anyTxHasWitness(this.transactions);
  }
  weight() {
    const base = this.byteLength(false, false);
    const total = this.byteLength(false, true);
    return base * 3 + total;
  }
  byteLength(headersOnly, allowWitness = true) {
    if (headersOnly || !this.transactions) return 84;
    return (
      84 +
      varuint$1.encodingLength(this.transactions.length) +
      this.transactions.reduce((a, x) => a + x.byteLength(allowWitness), 0)
    );
  }
  getHash() {
    return bcrypto$1.hash256(this.toBuffer(true));
  }
  getId() {
    return bufferutils$1.reverseBuffer(this.getHash()).toString('hex');
  }
  getUTCDate() {
    const date = new Date(0); // epoch
    date.setUTCSeconds(this.timestamp);
    return date;
  }
  // TODO: buffer, offset compatibility
  toBuffer(headersOnly) {
    const buffer = Buffer$1.allocUnsafe(this.byteLength(headersOnly));
    const bufferWriter = new bufferutils$1.BufferWriter(buffer);
    bufferWriter.writeInt32(this.version);
    bufferWriter.writeSlice(this.prevHash);
    bufferWriter.writeSlice(this.merkleRoot);
    bufferWriter.writeUInt32(this.timestamp);
    bufferWriter.writeUInt32(this.bits);
    bufferWriter.writeUInt32(this.nonce);
    if (headersOnly || !this.transactions) return buffer;
    varuint$1.encode(this.transactions.length, buffer, bufferWriter.offset);
    bufferWriter.offset += varuint$1.encode.bytes;
    this.transactions.forEach(tx => {
      const txSize = tx.byteLength(); // TODO: extract from toBuffer?
      tx.toBuffer(buffer, bufferWriter.offset);
      bufferWriter.offset += txSize;
    });
    return buffer;
  }
  toHex(headersOnly) {
    return this.toBuffer(headersOnly).toString('hex');
  }
  checkTxRoots() {
    // If the Block has segwit transactions but no witness commit,
    // there's no way it can be valid, so fail the check.
    const hasWitnessCommit = this.hasWitnessCommit();
    if (!hasWitnessCommit && this.hasWitness()) return false;
    return (
      this.__checkMerkleRoot() &&
      (hasWitnessCommit ? this.__checkWitnessCommit() : true)
    );
  }
  checkProofOfWork() {
    const hash = bufferutils$1.reverseBuffer(this.getHash());
    const target = Block$1.calculateTarget(this.bits);
    return hash.compare(target) <= 0;
  }
  __checkMerkleRoot() {
    if (!this.transactions) throw errorMerkleNoTxes;
    const actualMerkleRoot = Block$1.calculateMerkleRoot(this.transactions);
    return this.merkleRoot.compare(actualMerkleRoot) === 0;
  }
  __checkWitnessCommit() {
    if (!this.transactions) throw errorMerkleNoTxes;
    if (!this.hasWitnessCommit()) throw errorWitnessNotSegwit;
    const actualWitnessCommit = Block$1.calculateMerkleRoot(
      this.transactions,
      true,
    );
    return this.witnessCommit.compare(actualWitnessCommit) === 0;
  }
}
var Block_1 = Block$1;
function txesHaveWitnessCommit(transactions) {
  return (
    transactions instanceof Array &&
    transactions[0] &&
    transactions[0].ins &&
    transactions[0].ins instanceof Array &&
    transactions[0].ins[0] &&
    transactions[0].ins[0].witness &&
    transactions[0].ins[0].witness instanceof Array &&
    transactions[0].ins[0].witness.length > 0
  );
}
function anyTxHasWitness(transactions) {
  return (
    transactions instanceof Array &&
    transactions.some(
      tx =>
        typeof tx === 'object' &&
        tx.ins instanceof Array &&
        tx.ins.some(
          input =>
            typeof input === 'object' &&
            input.witness instanceof Array &&
            input.witness.length > 0,
        ),
    )
  );
}

var block = /*#__PURE__*/Object.defineProperty({
	Block: Block_1
}, '__esModule', {value: true});

var sha256d = createCommonjsModule(function (module, exports) {
Object.defineProperty(exports, '__esModule', { value: true });
// SHA-256 (+ HMAC and PBKDF2) for JavaScript.
//
// Written in 2014-2016 by Dmitry Chestnykh.
// Public domain, no warranty.
//
// Functions (accept and return Uint8Arrays):
//
//   sha256(message) -> hash
//   sha256.hmac(key, message) -> mac
//   sha256.pbkdf2(password, salt, rounds, dkLen) -> dk
//
//  Classes:
//
//   new sha256.Hash()
//   new sha256.HMAC(key)
//
exports.digestLength = 32;
exports.blockSize = 64;
// SHA-256 constants
const K = new Uint32Array([
  0x428a2f98,
  0x71374491,
  0xb5c0fbcf,
  0xe9b5dba5,
  0x3956c25b,
  0x59f111f1,
  0x923f82a4,
  0xab1c5ed5,
  0xd807aa98,
  0x12835b01,
  0x243185be,
  0x550c7dc3,
  0x72be5d74,
  0x80deb1fe,
  0x9bdc06a7,
  0xc19bf174,
  0xe49b69c1,
  0xefbe4786,
  0x0fc19dc6,
  0x240ca1cc,
  0x2de92c6f,
  0x4a7484aa,
  0x5cb0a9dc,
  0x76f988da,
  0x983e5152,
  0xa831c66d,
  0xb00327c8,
  0xbf597fc7,
  0xc6e00bf3,
  0xd5a79147,
  0x06ca6351,
  0x14292967,
  0x27b70a85,
  0x2e1b2138,
  0x4d2c6dfc,
  0x53380d13,
  0x650a7354,
  0x766a0abb,
  0x81c2c92e,
  0x92722c85,
  0xa2bfe8a1,
  0xa81a664b,
  0xc24b8b70,
  0xc76c51a3,
  0xd192e819,
  0xd6990624,
  0xf40e3585,
  0x106aa070,
  0x19a4c116,
  0x1e376c08,
  0x2748774c,
  0x34b0bcb5,
  0x391c0cb3,
  0x4ed8aa4a,
  0x5b9cca4f,
  0x682e6ff3,
  0x748f82ee,
  0x78a5636f,
  0x84c87814,
  0x8cc70208,
  0x90befffa,
  0xa4506ceb,
  0xbef9a3f7,
  0xc67178f2,
]);
function hashBlocks(w, v, p, pos, len) {
  let a;
  let b;
  let c;
  let d;
  let e;
  let f;
  let g;
  let h;
  let u;
  let i;
  let j;
  let t1;
  let t2;
  while (len >= 64) {
    a = v[0];
    b = v[1];
    c = v[2];
    d = v[3];
    e = v[4];
    f = v[5];
    g = v[6];
    h = v[7];
    for (i = 0; i < 16; i++) {
      j = pos + i * 4;
      w[i] =
        ((p[j] & 0xff) << 24) |
        ((p[j + 1] & 0xff) << 16) |
        ((p[j + 2] & 0xff) << 8) |
        (p[j + 3] & 0xff);
    }
    for (i = 16; i < 64; i++) {
      u = w[i - 2];
      t1 =
        ((u >>> 17) | (u << (32 - 17))) ^
        ((u >>> 19) | (u << (32 - 19))) ^
        (u >>> 10);
      u = w[i - 15];
      t2 =
        ((u >>> 7) | (u << (32 - 7))) ^
        ((u >>> 18) | (u << (32 - 18))) ^
        (u >>> 3);
      w[i] = ((t1 + w[i - 7]) | 0) + ((t2 + w[i - 16]) | 0);
    }
    for (i = 0; i < 64; i++) {
      t1 =
        ((((((e >>> 6) | (e << (32 - 6))) ^
          ((e >>> 11) | (e << (32 - 11))) ^
          ((e >>> 25) | (e << (32 - 25)))) +
          ((e & f) ^ (~e & g))) |
          0) +
          ((h + ((K[i] + w[i]) | 0)) | 0)) |
        0;
      t2 =
        ((((a >>> 2) | (a << (32 - 2))) ^
          ((a >>> 13) | (a << (32 - 13))) ^
          ((a >>> 22) | (a << (32 - 22)))) +
          ((a & b) ^ (a & c) ^ (b & c))) |
        0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    v[0] += a;
    v[1] += b;
    v[2] += c;
    v[3] += d;
    v[4] += e;
    v[5] += f;
    v[6] += g;
    v[7] += h;
    pos += 64;
    len -= 64;
  }
  return pos;
}
// Hash implements SHA256 hash algorithm.
class Hash {
  constructor() {
    this.digestLength = exports.digestLength;
    this.blockSize = exports.blockSize;
    this.finished = false; // indicates whether the hash was finalized
    // Note: Int32Array is used instead of Uint32Array for performance reasons.
    this.state = new Int32Array(8); // hash state
    this.temp = new Int32Array(64); // temporary state
    this.buffer = new Uint8Array(128); // buffer for data to hash
    this.bufferLength = 0; // number of bytes in buffer
    this.bytesHashed = 0; // number of total bytes hashed
    this.reset();
  }
  // Resets hash state making it possible
  // to re-use this instance to hash other data.
  reset() {
    this.state[0] = 0x6a09e667;
    this.state[1] = 0xbb67ae85;
    this.state[2] = 0x3c6ef372;
    this.state[3] = 0xa54ff53a;
    this.state[4] = 0x510e527f;
    this.state[5] = 0x9b05688c;
    this.state[6] = 0x1f83d9ab;
    this.state[7] = 0x5be0cd19;
    this.bufferLength = 0;
    this.bytesHashed = 0;
    this.finished = false;
    return this;
  }
  // Cleans internal buffers and re-initializes hash state.
  clean() {
    for (let i = 0; i < this.buffer.length; i++) {
      this.buffer[i] = 0;
    }
    for (let i = 0; i < this.temp.length; i++) {
      this.temp[i] = 0;
    }
    this.reset();
  }
  // Updates hash state with the given data.
  //
  // Optionally, length of the data can be specified to hash
  // fewer bytes than data.length.
  //
  // Throws error when trying to update already finalized hash:
  // instance must be reset to use it again.
  update(data, dataLength = data.length) {
    if (this.finished) {
      throw new Error("SHA256: can't update because hash was finished.");
    }
    let dataPos = 0;
    this.bytesHashed += dataLength;
    if (this.bufferLength > 0) {
      while (this.bufferLength < 64 && dataLength > 0) {
        this.buffer[this.bufferLength++] = data[dataPos++];
        dataLength--;
      }
      if (this.bufferLength === 64) {
        hashBlocks(this.temp, this.state, this.buffer, 0, 64);
        this.bufferLength = 0;
      }
    }
    if (dataLength >= 64) {
      dataPos = hashBlocks(this.temp, this.state, data, dataPos, dataLength);
      dataLength %= 64;
    }
    while (dataLength > 0) {
      this.buffer[this.bufferLength++] = data[dataPos++];
      dataLength--;
    }
    return this;
  }
  // Finalizes hash state and puts hash into out.
  //
  // If hash was already finalized, puts the same value.
  finish(out) {
    if (!this.finished) {
      const bytesHashed = this.bytesHashed;
      const left = this.bufferLength;
      const bitLenHi = (bytesHashed / 0x20000000) | 0;
      const bitLenLo = bytesHashed << 3;
      const padLength = bytesHashed % 64 < 56 ? 64 : 128;
      this.buffer[left] = 0x80;
      for (let i = left + 1; i < padLength - 8; i++) {
        this.buffer[i] = 0;
      }
      this.buffer[padLength - 8] = (bitLenHi >>> 24) & 0xff;
      this.buffer[padLength - 7] = (bitLenHi >>> 16) & 0xff;
      this.buffer[padLength - 6] = (bitLenHi >>> 8) & 0xff;
      this.buffer[padLength - 5] = (bitLenHi >>> 0) & 0xff;
      this.buffer[padLength - 4] = (bitLenLo >>> 24) & 0xff;
      this.buffer[padLength - 3] = (bitLenLo >>> 16) & 0xff;
      this.buffer[padLength - 2] = (bitLenLo >>> 8) & 0xff;
      this.buffer[padLength - 1] = (bitLenLo >>> 0) & 0xff;
      hashBlocks(this.temp, this.state, this.buffer, 0, padLength);
      this.finished = true;
    }
    for (let i = 0; i < 8; i++) {
      out[i * 4 + 0] = (this.state[i] >>> 24) & 0xff;
      out[i * 4 + 1] = (this.state[i] >>> 16) & 0xff;
      out[i * 4 + 2] = (this.state[i] >>> 8) & 0xff;
      out[i * 4 + 3] = (this.state[i] >>> 0) & 0xff;
    }
    return this;
  }
  // Returns the final hash digest.
  digest() {
    const out = new Uint8Array(this.digestLength);
    this.finish(out);
    return out;
  }
  // Internal function for use in HMAC for optimization.
  _saveState(out) {
    for (let i = 0; i < this.state.length; i++) {
      out[i] = this.state[i];
    }
  }
  // Internal function for use in HMAC for optimization.
  _restoreState(from, bytesHashed) {
    for (let i = 0; i < this.state.length; i++) {
      this.state[i] = from[i];
    }
    this.bytesHashed = bytesHashed;
    this.finished = false;
    this.bufferLength = 0;
  }
}
exports.Hash = Hash;
// Returns SHA256 hash of data.
function hash(data) {
  const h = new Hash().update(data);
  const digest = h.digest();
  h.clean();
  return digest;
}
exports.hash = hash;
function sha256Midstate(data) {
  let d = data;
  if (data.length > exports.blockSize) {
    d = data.slice(0, exports.blockSize);
  }
  const h = new Hash();
  h.reset();
  h.update(Uint8Array.from(d));
  const midstate = Buffer$1.alloc(exports.digestLength);
  for (let i = 0; i < 8; i++) {
    midstate[i * 4 + 0] = (h.state[i] >>> 24) & 0xff;
    midstate[i * 4 + 1] = (h.state[i] >>> 16) & 0xff;
    midstate[i * 4 + 2] = (h.state[i] >>> 8) & 0xff;
    midstate[i * 4 + 3] = (h.state[i] >>> 0) & 0xff;
  }
  return midstate;
}
exports.sha256Midstate = sha256Midstate;
});

var __importStar$2 =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };



const bcrypto = __importStar$2(crypto$2);

/**
 * returns true if the issuance's token amount is not 0x00 or null buffer.
 * @param issuance issuance to test
 */
function hasTokenAmount(issuance) {
  if (issuance.tokenAmount && issuance.tokenAmount.length > 1) return true;
  return false;
}
var hasTokenAmount_1 = hasTokenAmount;
/**
 * Checks if a contract given as parameter is valid or not.
 * @param contract contract to validate.
 */
function validateIssuanceContract(contract) {
  const precisionIsValid = contract.precision >= 0 && contract.precision <= 8;
  return precisionIsValid;
}
var validateIssuanceContract_1 = validateIssuanceContract;
/**
 * Returns the SHA256 value of the JSON encoded Issuance contract.
 * @param contract the contract to digest.
 */
function hashContract(contract) {
  if (!validateIssuanceContract(contract))
    throw new Error('Invalid asset contract');
  return bcrypto.sha256(Buffer$1.from(JSON.stringify(contract)));
}
var hashContract_1 = hashContract;
/**
 * Returns an Issuance object for issuance transaction input.
 * @param assetAmount the number of asset to issue.
 * @param tokenAmount the number of token to issue.
 * @param precision the number of digit after the decimal point (8 for satoshi).
 * @param contract the asset ricarding contract of the issuance.
 */
function newIssuance(assetAmount, tokenAmount, precision = 8, contract) {
  if (assetAmount < 0) throw new Error('Invalid asset amount');
  if (tokenAmount < 0) throw new Error('Invalid token amount');
  if (precision < 0 || precision > 8) throw new Error('Invalid precision');
  let contractHash = Buffer$1.alloc(32);
  if (contract) {
    if (contract.precision !== precision)
      throw new Error('precision is not equal to the asset contract precision');
    contractHash = hashContract(contract);
  }
  const iss = {
    assetAmount: toConfidentialAssetAmount(assetAmount, precision),
    tokenAmount: toConfidentialTokenAmount(tokenAmount, precision),
    assetBlindingNonce: Buffer$1.alloc(32),
    // in case of issuance, the asset entropy = the contract hash.
    assetEntropy: contractHash,
  };
  return iss;
}
var newIssuance_1 = newIssuance;
/**
 * Generate the entropy.
 * @param outPoint the prevout point used to compute the entropy.
 * @param contractHash the 32 bytes contract hash.
 */
function generateEntropy(outPoint, contractHash = Buffer$1.alloc(32)) {
  if (outPoint.txHash.length !== 32) {
    throw new Error('Invalid txHash length');
  }
  const tBuffer = Buffer$1.allocUnsafe(36);
  const s = new bufferutils$1.BufferWriter(tBuffer, 0);
  s.writeSlice(outPoint.txHash);
  s.writeInt32(outPoint.vout);
  const prevoutHash = bcrypto.hash256(s.buffer);
  const concatened = Buffer$1.concat([prevoutHash, contractHash]);
  return sha256d.sha256Midstate(concatened);
}
var generateEntropy_1 = generateEntropy;
/**
 * calculate the asset tag from a given entropy.
 * @param entropy the entropy used to compute the asset tag.
 */
function calculateAsset(entropy) {
  if (entropy.length !== 32) throw new Error('Invalid entropy length');
  const kZero = Buffer$1.alloc(32);
  return sha256d.sha256Midstate(Buffer$1.concat([entropy, kZero]));
}
var calculateAsset_1 = calculateAsset;
/**
 * Compute the reissuance token.
 * @param entropy the entropy used to compute the reissuance token.
 * @param confidential true if confidential.
 */
function calculateReissuanceToken(entropy, confidential = false) {
  if (entropy.length !== 32) throw new Error('Invalid entropy length');
  const buffer = Buffer$1.alloc(32);
  confidential ? (buffer[0] = 2) : (buffer[0] = 1);
  return sha256d.sha256Midstate(Buffer$1.concat([entropy, buffer]));
}
var calculateReissuanceToken_1 = calculateReissuanceToken;
/**
 * converts asset amount to confidential value.
 * @param assetAmount the asset amount.
 * @param precision the precision, 8 by default.
 */
function toConfidentialAssetAmount(assetAmount, precision = 8) {
  const amount = Math.pow(10, precision) * assetAmount;
  return confidential$2.satoshiToConfidentialValue(amount);
}
/**
 * converts token amount to confidential value.
 * @param assetAmount the token amount.
 * @param precision the precision, 8 by default.
 */
function toConfidentialTokenAmount(tokenAmount, precision = 8) {
  if (tokenAmount === 0) return Buffer$1.from('00', 'hex');
  return toConfidentialAssetAmount(tokenAmount, precision);
}

var issuance = /*#__PURE__*/Object.defineProperty({
	hasTokenAmount: hasTokenAmount_1,
	validateIssuanceContract: validateIssuanceContract_1,
	hashContract: hashContract_1,
	newIssuance: newIssuance_1,
	generateEntropy: generateEntropy_1,
	calculateAsset: calculateAsset_1,
	calculateReissuanceToken: calculateReissuanceToken_1
}, '__esModule', {value: true});

var __awaiter =
  (commonjsGlobal && commonjsGlobal.__awaiter) ||
  function(thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function(resolve, reject) {
      function fulfilled(value) {
        try {
          step(generator.next(value));
        } catch (e) {
          reject(e);
        }
      }
      function rejected(value) {
        try {
          step(generator['throw'](value));
        } catch (e) {
          reject(e);
        }
      }
      function step(result) {
        result.done
          ? resolve(result.value)
          : new P(function(resolve) {
              resolve(result.value);
            }).then(fulfilled, rejected);
      }
      step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
  };
var __importStar$1 =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };

const confidential$1 = __importStar$1(confidential$2);
const varuint = __importStar$1(require$$1);







const payments$1 = __importStar$1(payments$3);
const bscript = __importStar$1(script$1);



/**
 * These are the default arguments for a Psbt instance.
 */
const DEFAULT_OPTS = {
  /**
   * A bitcoinjs Network object. This is only used if you pass an `address`
   * parameter to addOutput. Otherwise it is not needed and can be left default.
   */
  network: networks$2.liquid,
  /**
   * When extractTransaction is called, the fee rate is checked.
   * THIS IS NOT TO BE RELIED ON.
   * It is only here as a last ditch effort to prevent sending a 500 BTC fee etc.
   */
  maximumFeeRate: 5000,
};
/**
 * Psbt class can parse and generate a PSBT binary based off of the BIP174.
 * There are 6 roles that this class fulfills. (Explained in BIP174)
 *
 * Creator: This can be done with `new Psbt()`
 * Updater: This can be done with `psbt.addInput(input)`, `psbt.addInputs(inputs)`,
 *   `psbt.addOutput(output)`, `psbt.addOutputs(outputs)` when you are looking to
 *   add new inputs and outputs to the PSBT, and `psbt.updateGlobal(itemObject)`,
 *   `psbt.updateInput(itemObject)`, `psbt.updateOutput(itemObject)`
 *   addInput requires hash: Buffer | string; and index: number; as attributes
 *   and can also include any attributes that are used in updateInput method.
 *   addOutput requires script: Buffer; and value: number; and likewise can include
 *   data for updateOutput.
 *   For a list of what attributes should be what types. Check the bip174 library.
 *   Also, check the integration tests for some examples of usage.
 * Signer: There are a few methods. signAllInputs and signAllInputsAsync, which will search all input
 *   information for your pubkey or pubkeyhash, and only sign inputs where it finds
 *   your info. Or you can explicitly sign a specific input with signInput and
 *   signInputAsync. For the async methods you can create a SignerAsync object
 *   and use something like a hardware wallet to sign with. (You must implement this)
 * Combiner: psbts can be combined easily with `psbt.combine(psbt2, psbt3, psbt4 ...)`
 *   the psbt calling combine will always have precedence when a conflict occurs.
 *   Combine checks if the internal bitcoin transaction is the same, so be sure that
 *   all sequences, version, locktime, etc. are the same before combining.
 * Input Finalizer: This role is fairly important. Not only does it need to construct
 *   the input scriptSigs and witnesses, but it SHOULD verify the signatures etc.
 *   Before running `psbt.finalizeAllInputs()` please run `psbt.validateSignaturesOfAllInputs()`
 *   Running any finalize method will delete any data in the input(s) that are no longer
 *   needed due to the finalized scripts containing the information.
 * Transaction Extractor: This role will perform some checks before returning a
 *   Transaction object. Such as fee rate not being larger than maximumFeeRate etc.
 */
class Psbt$1 {
  constructor(opts = {}, data = new bip174_1.Psbt(new PsbtTransaction())) {
    this.data = data;
    // set defaults
    this.opts = Object.assign({}, DEFAULT_OPTS, opts);
    this.__CACHE = {
      __NON_WITNESS_UTXO_TX_CACHE: [],
      __NON_WITNESS_UTXO_BUF_CACHE: [],
      __TX_IN_CACHE: {},
      __TX: this.data.globalMap.unsignedTx.tx,
    };
    if (this.data.inputs.length === 0) this.setVersion(2);
    // Make data hidden when enumerating
    const dpew = (obj, attr, enumerable, writable) =>
      Object.defineProperty(obj, attr, {
        enumerable,
        writable,
      });
    dpew(this, '__CACHE', false, true);
    dpew(this, 'opts', false, true);
  }
  static fromBase64(data, opts = {}) {
    const buffer = Buffer$1.from(data, 'base64');
    return this.fromBuffer(buffer, opts);
  }
  static fromHex(data, opts = {}) {
    const buffer = Buffer$1.from(data, 'hex');
    return this.fromBuffer(buffer, opts);
  }
  static fromBuffer(buffer, opts = {}) {
    const psbtBase = bip174_1.Psbt.fromBuffer(buffer, transactionFromBuffer);
    const psbt = new Psbt$1(opts, psbtBase);
    checkTxForDupeIns(psbt.__CACHE.__TX, psbt.__CACHE);
    return psbt;
  }
  get inputCount() {
    return this.data.inputs.length;
  }
  combine(...those) {
    this.data.combine(...those.map(o => o.data));
    return this;
  }
  clone() {
    // TODO: more efficient cloning
    const res = Psbt$1.fromBuffer(this.data.toBuffer());
    res.opts = JSON.parse(JSON.stringify(this.opts));
    return res;
  }
  setMaximumFeeRate(satoshiPerByte) {
    check32Bit(satoshiPerByte); // 42.9 BTC per byte IS excessive... so throw
    this.opts.maximumFeeRate = satoshiPerByte;
  }
  setVersion(version) {
    check32Bit(version);
    checkInputsForPartialSig(this.data.inputs, 'setVersion');
    const c = this.__CACHE;
    c.__TX.version = version;
    c.__EXTRACTED_TX = undefined;
    return this;
  }
  setLocktime(locktime) {
    check32Bit(locktime);
    checkInputsForPartialSig(this.data.inputs, 'setLocktime');
    const c = this.__CACHE;
    c.__TX.locktime = locktime;
    c.__EXTRACTED_TX = undefined;
    return this;
  }
  setInputSequence(inputIndex, sequence) {
    check32Bit(sequence);
    checkInputsForPartialSig(this.data.inputs, 'setInputSequence');
    const c = this.__CACHE;
    if (c.__TX.ins.length <= inputIndex) {
      throw new Error('Input index too high');
    }
    c.__TX.ins[inputIndex].sequence = sequence;
    c.__EXTRACTED_TX = undefined;
    return this;
  }
  addInputs(inputDatas) {
    inputDatas.forEach(inputData => this.addInput(inputData));
    return this;
  }
  addInput(inputData) {
    if (
      arguments.length > 1 ||
      !inputData ||
      inputData.hash === undefined ||
      inputData.index === undefined
    ) {
      throw new Error(
        `Invalid arguments for Psbt.addInput. ` +
          `Requires single object with at least [hash] and [index]`,
      );
    }
    checkInputsForPartialSig(this.data.inputs, 'addInput');
    const c = this.__CACHE;
    this.data.addInput(inputData);
    const txIn = c.__TX.ins[c.__TX.ins.length - 1];
    checkTxInputCache(c, txIn);
    const inputIndex = this.data.inputs.length - 1;
    const input = this.data.inputs[inputIndex];
    if (input.nonWitnessUtxo) {
      addNonWitnessTxCache(this.__CACHE, input, inputIndex);
    }
    c.__FEE = undefined;
    c.__FEE_RATE = undefined;
    c.__EXTRACTED_TX = undefined;
    return this;
  }
  addIssuance(args, inputIndex) {
    // check the amounts.
    if (args.assetAmount <= 0)
      throw new Error('asset amount must be greater than zero.');
    if (args.tokenAmount < 0) throw new Error('token amount must be positive.');
    if (inputIndex && !this.data.inputs[inputIndex]) {
      throw new Error(`The input ${inputIndex} does not exist.`);
      // check if the input is available for issuance.
    } else {
      // verify if there is at least one input available.
      if (this.__CACHE.__TX.ins.filter(i => !i.issuance).length === 0)
        throw new Error(
          'transaction needs at least one input without issuance data.',
        );
      // search and extract the input index.
      inputIndex = this.__CACHE.__TX.ins.findIndex(i => !i.issuance);
    }
    if (this.__CACHE.__TX.ins[inputIndex].issuance)
      throw new Error(`The input ${inputIndex} already has issuance data.`);
    const assetAddrIsConfidential = address$1.isConfidential(args.assetAddress);
    const tokenAddrIsConfidential = args.tokenAddress
      ? address$1.isConfidential(args.tokenAddress)
      : undefined;
    if (
      tokenAddrIsConfidential !== undefined &&
      assetAddrIsConfidential !== tokenAddrIsConfidential
    ) {
      throw new Error(
        'tokenAddress and assetAddress are not of the same type (confidential or unconfidential).',
      );
    }
    const { hash, index } = this.__CACHE.__TX.ins[inputIndex];
    // create an issuance object using the vout and the args
    const issuance$1 = issuance.newIssuance(
      args.assetAmount,
      args.tokenAmount,
      args.precision,
      args.contract,
    );
    // generate the entropy
    const entropy = issuance.generateEntropy(
      { txHash: hash, vout: index },
      issuance$1.assetEntropy,
    );
    // add the issuance to the input.
    this.__CACHE.__TX.ins[inputIndex].issuance = issuance$1;
    const kOne = Buffer$1.from('01', 'hex');
    const asset = Buffer$1.concat([kOne, issuance.calculateAsset(entropy)]);
    const assetScript = address$1.toOutputScript(args.assetAddress, args.net);
    // send the asset amount to the asset address.
    this.addOutput({
      value: issuance$1.assetAmount,
      script: assetScript,
      asset,
      nonce: Buffer$1.from('00', 'hex'),
    });
    // check if the token amount is not 0
    if (args.tokenAmount !== 0) {
      if (!args.tokenAddress)
        throw new Error("tokenAddress can't be undefined if tokenAmount > 0");
      const token = Buffer$1.concat([
        kOne,
        issuance.calculateReissuanceToken(
          entropy,
          address$1.isConfidential(args.tokenAddress),
        ),
      ]);
      const tokenScript = address$1.toOutputScript(args.tokenAddress, args.net);
      // send the token amount to the token address.
      this.addOutput({
        script: tokenScript,
        value: issuance$1.tokenAmount,
        asset: token,
        nonce: Buffer$1.from('00', 'hex'),
      });
    }
    return this;
  }
  addOutputs(outputDatas) {
    outputDatas.forEach(outputData => this.addOutput(outputData));
    return this;
  }
  addOutput(outputData) {
    if (
      arguments.length > 1 ||
      !outputData ||
      outputData.value === undefined ||
      (outputData.address === undefined && outputData.script === undefined)
    ) {
      throw new Error(
        `Invalid arguments for Psbt.addOutput. ` +
          `Requires single object with at least [script or address] and [value]`,
      );
    }
    checkInputsForPartialSig(this.data.inputs, 'addOutput');
    const { address } = outputData;
    if (typeof address === 'string') {
      const { network } = this.opts;
      const script = address$1.toOutputScript(address, network);
      outputData = Object.assign(outputData, { script });
    }
    const c = this.__CACHE;
    this.data.addOutput(outputData);
    c.__FEE = undefined;
    c.__FEE_RATE = undefined;
    c.__EXTRACTED_TX = undefined;
    return this;
  }
  extractTransaction(disableFeeCheck) {
    if (!this.data.inputs.every(isFinalized)) throw new Error('Not finalized');
    const c = this.__CACHE;
    if (!disableFeeCheck) {
      checkFees(this, c, this.opts);
    }
    if (c.__EXTRACTED_TX) return c.__EXTRACTED_TX;
    const tx = c.__TX.clone();
    inputFinalizeGetAmts(this.data.inputs, tx, c, true);
    return tx;
  }
  getFeeRate() {
    return getTxCacheValue(
      '__FEE_RATE',
      'fee rate',
      this.data.inputs,
      this.__CACHE,
    );
  }
  getFee() {
    return getTxCacheValue('__FEE', 'fee', this.data.inputs, this.__CACHE);
  }
  finalizeAllInputs() {
    utils_1.checkForInput(this.data.inputs, 0); // making sure we have at least one
    range(this.data.inputs.length).forEach(idx => this.finalizeInput(idx));
    return this;
  }
  finalizeInput(inputIndex) {
    const input = utils_1.checkForInput(this.data.inputs, inputIndex);
    const { script, isP2SH, isP2WSH, isSegwit } = getScriptFromInput(
      inputIndex,
      input,
      this.__CACHE,
    );
    if (!script) throw new Error(`No script found for input #${inputIndex}`);
    const scriptType = classifyScript(script);
    if (!canFinalize(input, script, scriptType))
      throw new Error(`Can not finalize input #${inputIndex}`);
    checkPartialSigSighashes(input);
    const { finalScriptSig, finalScriptWitness } = getFinalScripts(
      script,
      scriptType,
      input.partialSig,
      isSegwit,
      isP2SH,
      isP2WSH,
    );
    if (finalScriptSig) this.data.updateInput(inputIndex, { finalScriptSig });
    if (finalScriptWitness)
      this.data.updateInput(inputIndex, { finalScriptWitness });
    if (!finalScriptSig && !finalScriptWitness)
      throw new Error(`Unknown error finalizing input #${inputIndex}`);
    this.data.clearFinalizedInput(inputIndex);
    return this;
  }
  validateSignaturesOfAllInputs() {
    utils_1.checkForInput(this.data.inputs, 0); // making sure we have at least one
    const results = range(this.data.inputs.length).map(idx =>
      this.validateSignaturesOfInput(idx),
    );
    return results.reduce((final, res) => res === true && final, true);
  }
  validateSignaturesOfInput(inputIndex, pubkey) {
    const input = this.data.inputs[inputIndex];
    const partialSig = (input || {}).partialSig;
    if (!input || !partialSig || partialSig.length < 1)
      throw new Error('No signatures to validate');
    const mySigs = pubkey
      ? partialSig.filter(sig => sig.pubkey.equals(pubkey))
      : partialSig;
    if (mySigs.length < 1) throw new Error('No signatures for this pubkey');
    const results = [];
    let hashCache;
    let scriptCache;
    let sighashCache;
    for (const pSig of mySigs) {
      const sig = bscript.signature.decode(pSig.signature);
      const { hash, script } =
        sighashCache !== sig.hashType
          ? getHashForSig(
              inputIndex,
              Object.assign({}, input, { sighashType: sig.hashType }),
              this.__CACHE,
            )
          : { hash: hashCache, script: scriptCache };
      sighashCache = sig.hashType;
      hashCache = hash;
      scriptCache = script;
      checkScriptForPubkey(pSig.pubkey, script, 'verify');
      const keypair = ecpair.fromPublicKey(pSig.pubkey);
      results.push(keypair.verify(hash, sig.signature));
    }
    return results.every(res => res === true);
  }
  signAllInputsHD(
    hdKeyPair,
    sighashTypes = [transaction.Transaction.SIGHASH_ALL],
  ) {
    if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
      throw new Error('Need HDSigner to sign input');
    }
    const results = [];
    for (const i of range(this.data.inputs.length)) {
      try {
        this.signInputHD(i, hdKeyPair, sighashTypes);
        results.push(true);
      } catch (err) {
        results.push(false);
      }
    }
    if (results.every(v => v === false)) {
      throw new Error('No inputs were signed');
    }
    return this;
  }
  signAllInputsHDAsync(
    hdKeyPair,
    sighashTypes = [transaction.Transaction.SIGHASH_ALL],
  ) {
    return new Promise((resolve, reject) => {
      if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
        return reject(new Error('Need HDSigner to sign input'));
      }
      const results = [];
      const promises = [];
      for (const i of range(this.data.inputs.length)) {
        promises.push(
          this.signInputHDAsync(i, hdKeyPair, sighashTypes).then(
            () => {
              results.push(true);
            },
            () => {
              results.push(false);
            },
          ),
        );
      }
      return Promise.all(promises).then(() => {
        if (results.every(v => v === false)) {
          return reject(new Error('No inputs were signed'));
        }
        resolve();
      });
    });
  }
  signInputHD(
    inputIndex,
    hdKeyPair,
    sighashTypes = [transaction.Transaction.SIGHASH_ALL],
  ) {
    if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
      throw new Error('Need HDSigner to sign input');
    }
    const signers = getSignersFromHD(inputIndex, this.data.inputs, hdKeyPair);
    signers.forEach(signer => this.signInput(inputIndex, signer, sighashTypes));
    return this;
  }
  signInputHDAsync(
    inputIndex,
    hdKeyPair,
    sighashTypes = [transaction.Transaction.SIGHASH_ALL],
  ) {
    return new Promise((resolve, reject) => {
      if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
        return reject(new Error('Need HDSigner to sign input'));
      }
      const signers = getSignersFromHD(inputIndex, this.data.inputs, hdKeyPair);
      const promises = signers.map(signer =>
        this.signInputAsync(inputIndex, signer, sighashTypes),
      );
      return Promise.all(promises)
        .then(() => {
          resolve();
        })
        .catch(reject);
    });
  }
  signAllInputs(
    keyPair,
    sighashTypes = [transaction.Transaction.SIGHASH_ALL],
  ) {
    if (!keyPair || !keyPair.publicKey)
      throw new Error('Need Signer to sign input');
    // TODO: Add a pubkey/pubkeyhash cache to each input
    // as input information is added, then eventually
    // optimize this method.
    const results = [];
    for (const i of range(this.data.inputs.length)) {
      try {
        this.signInput(i, keyPair, sighashTypes);
        results.push(true);
      } catch (err) {
        results.push(false);
      }
    }
    if (results.every(v => v === false)) {
      throw new Error('No inputs were signed');
    }
    return this;
  }
  signAllInputsAsync(
    keyPair,
    sighashTypes = [transaction.Transaction.SIGHASH_ALL],
  ) {
    return new Promise((resolve, reject) => {
      if (!keyPair || !keyPair.publicKey)
        return reject(new Error('Need Signer to sign input'));
      // TODO: Add a pubkey/pubkeyhash cache to each input
      // as input information is added, then eventually
      // optimize this method.
      const results = [];
      const promises = [];
      for (const [i] of this.data.inputs.entries()) {
        promises.push(
          this.signInputAsync(i, keyPair, sighashTypes).then(
            () => {
              results.push(true);
            },
            () => {
              results.push(false);
            },
          ),
        );
      }
      return Promise.all(promises).then(() => {
        if (results.every(v => v === false)) {
          return reject(new Error('No inputs were signed'));
        }
        resolve();
      });
    });
  }
  signInput(
    inputIndex,
    keyPair,
    sighashTypes = [transaction.Transaction.SIGHASH_ALL],
  ) {
    if (!keyPair || !keyPair.publicKey)
      throw new Error('Need Signer to sign input');
    const { hash, sighashType } = getHashAndSighashType(
      this.data.inputs,
      inputIndex,
      keyPair.publicKey,
      this.__CACHE,
      sighashTypes,
    );
    const partialSig = [
      {
        pubkey: keyPair.publicKey,
        signature: bscript.signature.encode(keyPair.sign(hash), sighashType),
      },
    ];
    this.data.updateInput(inputIndex, { partialSig });
    return this;
  }
  signInputAsync(
    inputIndex,
    keyPair,
    sighashTypes = [transaction.Transaction.SIGHASH_ALL],
  ) {
    return new Promise((resolve, reject) => {
      if (!keyPair || !keyPair.publicKey)
        return reject(new Error('Need Signer to sign input'));
      const { hash, sighashType } = getHashAndSighashType(
        this.data.inputs,
        inputIndex,
        keyPair.publicKey,
        this.__CACHE,
        sighashTypes,
      );
      Promise.resolve(keyPair.sign(hash)).then(signature => {
        const partialSig = [
          {
            pubkey: keyPair.publicKey,
            signature: bscript.signature.encode(signature, sighashType),
          },
        ];
        this.data.updateInput(inputIndex, { partialSig });
        resolve();
      });
    });
  }
  toBuffer() {
    return this.data.toBuffer();
  }
  toHex() {
    return this.data.toHex();
  }
  toBase64() {
    return this.data.toBase64();
  }
  updateGlobal(updateData) {
    this.data.updateGlobal(updateData);
    return this;
  }
  updateInput(inputIndex, updateData) {
    if (updateData.witnessUtxo) {
      const { witnessUtxo } = updateData;
      const script = Buffer$1.isBuffer(witnessUtxo.script)
        ? witnessUtxo.script
        : Buffer$1.from(witnessUtxo.script, 'hex');
      const value = Buffer$1.isBuffer(witnessUtxo.value)
        ? witnessUtxo.value
        : typeof witnessUtxo.value === 'string'
        ? Buffer$1.from(witnessUtxo.value, 'hex')
        : confidential$1.satoshiToConfidentialValue(witnessUtxo.value);
      // if the asset is a string, by checking the first byte we can determine if
      // it's an asset commitment, in this case we decode the hex string as buffer,
      // or if it's an asset hash, in this case we put the unconf prefix in front of the reversed the buffer
      const asset = Buffer$1.isBuffer(witnessUtxo.asset)
        ? witnessUtxo.asset
        : witnessUtxo.asset.startsWith('0a') ||
          witnessUtxo.asset.startsWith('0b')
        ? Buffer$1.from(witnessUtxo.asset, 'hex')
        : Buffer$1.concat([
            Buffer$1.alloc(1, 1),
            bufferutils$1.reverseBuffer(Buffer$1.from(witnessUtxo.asset, 'hex')),
          ]);
      const nonce = witnessUtxo.nonce
        ? Buffer$1.isBuffer(witnessUtxo.nonce)
          ? witnessUtxo.nonce
          : Buffer$1.from(witnessUtxo.nonce, 'hex')
        : Buffer$1.alloc(1, 0);
      const rangeProof = witnessUtxo.rangeProof
        ? Buffer$1.isBuffer(witnessUtxo.rangeProof)
          ? witnessUtxo.rangeProof
          : Buffer$1.from(witnessUtxo.rangeProof, 'hex')
        : undefined;
      const surjectionProof = witnessUtxo.surjectionProof
        ? Buffer$1.isBuffer(witnessUtxo.surjectionProof)
          ? witnessUtxo.surjectionProof
          : Buffer$1.from(witnessUtxo.surjectionProof, 'hex')
        : undefined;
      updateData = Object.assign(updateData, {
        witnessUtxo: {
          script,
          value,
          asset,
          nonce,
          rangeProof,
          surjectionProof,
        },
      });
    }
    this.data.updateInput(inputIndex, updateData);
    if (updateData.nonWitnessUtxo) {
      addNonWitnessTxCache(
        this.__CACHE,
        this.data.inputs[inputIndex],
        inputIndex,
      );
    }
    return this;
  }
  updateOutput(outputIndex, updateData) {
    this.data.updateOutput(outputIndex, updateData);
    return this;
  }
  blindOutputs(blindingDataLike, blindingPubkeys, opts) {
    return this.rawBlindOutputs(
      blindingDataLike,
      blindingPubkeys,
      undefined,
      undefined,
      opts,
    );
  }
  blindOutputsByIndex(
    inputsBlindingData,
    outputsBlindingPubKeys,
    issuancesBlindingKeys,
    opts,
  ) {
    const blindingPrivKeysArgs = range(this.__CACHE.__TX.ins.length).map(
      inputIndex => inputsBlindingData.get(inputIndex),
    );
    const blindingPrivKeysIssuancesArgs = issuancesBlindingKeys
      ? range(this.__CACHE.__TX.ins.length).map(inputIndex =>
          issuancesBlindingKeys.get(inputIndex),
        )
      : [];
    const outputIndexes = [];
    const blindingPublicKey = [];
    for (const [outputIndex, pubBlindingKey] of outputsBlindingPubKeys) {
      outputIndexes.push(outputIndex);
      blindingPublicKey.push(pubBlindingKey);
    }
    return this.rawBlindOutputs(
      blindingPrivKeysArgs,
      blindingPublicKey,
      blindingPrivKeysIssuancesArgs,
      outputIndexes,
      opts,
    );
  }
  addUnknownKeyValToGlobal(keyVal) {
    this.data.addUnknownKeyValToGlobal(keyVal);
    return this;
  }
  addUnknownKeyValToInput(inputIndex, keyVal) {
    this.data.addUnknownKeyValToInput(inputIndex, keyVal);
    return this;
  }
  addUnknownKeyValToOutput(outputIndex, keyVal) {
    this.data.addUnknownKeyValToOutput(outputIndex, keyVal);
    return this;
  }
  clearFinalizedInput(inputIndex) {
    this.data.clearFinalizedInput(inputIndex);
    return this;
  }
  rawBlindOutputs(
    blindingDataLike,
    blindingPubkeys,
    issuanceBlindingPrivKeys = [],
    outputIndexes,
    opts,
  ) {
    return __awaiter(this, void 0, void 0, function*() {
      if (this.data.inputs.some(v => !v.nonWitnessUtxo && !v.witnessUtxo))
        throw new Error(
          'All inputs must contain a non witness utxo or a witness utxo',
        );
      const c = this.__CACHE;
      if (c.__TX.ins.length !== blindingDataLike.length) {
        throw new Error(
          'blindingDataLike length does not match the number of inputs (undefined for unconfidential utxo)',
        );
      }
      if (!outputIndexes) {
        outputIndexes = [];
        // fill the outputIndexes array with all the output index (except the fee output)
        c.__TX.outs.forEach((out, index) => {
          if (out.script.length > 0) outputIndexes.push(index);
        });
      }
      if (outputIndexes.length !== blindingPubkeys.length)
        throw new Error(
          'not enough blinding public keys to blind the requested outputs',
        );
      const witnesses = this.data.inputs.map((input, index) => {
        if (input.nonWitnessUtxo) {
          const prevTx = nonWitnessUtxoTxFromCache(c, input, index);
          const prevoutIndex = c.__TX.ins[index].index;
          return prevTx.outs[prevoutIndex];
        }
        if (input.witnessUtxo) {
          return input.witnessUtxo;
        }
        throw new Error('input data needs witness utxo or nonwitness utxo');
      });
      const inputsBlindingData = yield Promise.all(
        blindingDataLike.map((data, i) => toBlindingData(data, witnesses[i])),
      );
      // loop over inputs and create blindingData object in case of issuance
      let i = 0;
      for (const input of this.__CACHE.__TX.ins) {
        if (input.issuance) {
          const isConfidentialIssuance =
            issuanceBlindingPrivKeys && issuanceBlindingPrivKeys[i]
              ? true
              : false;
          const entropy = issuance.generateEntropy(
            { txHash: input.hash, vout: input.index },
            input.issuance.assetEntropy,
          );
          const asset = issuance.calculateAsset(entropy);
          const value = confidential$1
            .confidentialValueToSatoshi(input.issuance.assetAmount)
            .toString(10);
          const blindingDataIssuance = {
            value,
            asset,
            assetBlindingFactor: isConfidentialIssuance
              ? randomBytes()
              : transaction.ZERO,
            valueBlindingFactor: isConfidentialIssuance
              ? randomBytes()
              : transaction.ZERO,
          };
          inputsBlindingData.unshift(blindingDataIssuance);
          if (isConfidentialIssuance) {
            const assetCommitment = yield confidential$1.assetCommitment(
              asset,
              blindingDataIssuance.assetBlindingFactor,
            );
            const valueCommitment = yield confidential$1.valueCommitment(
              value,
              assetCommitment,
              blindingDataIssuance.valueBlindingFactor,
            );
            const rangeProof = yield confidential$1.rangeProofWithoutNonceHash(
              value,
              issuanceBlindingPrivKeys[i].assetKey,
              asset,
              blindingDataIssuance.assetBlindingFactor,
              blindingDataIssuance.valueBlindingFactor,
              valueCommitment,
              Buffer$1.alloc(0),
              '1',
              0,
              52,
            );
            this.__CACHE.__TX.ins[i].issuanceRangeProof = rangeProof;
            this.__CACHE.__TX.ins[i].issuance.assetAmount = valueCommitment;
          }
          if (issuance.hasTokenAmount(input.issuance)) {
            const token = issuance.calculateReissuanceToken(
              entropy,
              isConfidentialIssuance,
            );
            const tokenValue = confidential$1
              .confidentialValueToSatoshi(input.issuance.tokenAmount)
              .toString(10);
            const blindingDataIssuance = {
              value: tokenValue,
              asset: token,
              assetBlindingFactor: isConfidentialIssuance
                ? randomBytes()
                : transaction.ZERO,
              valueBlindingFactor: isConfidentialIssuance
                ? randomBytes()
                : transaction.ZERO,
            };
            inputsBlindingData.unshift(blindingDataIssuance);
            if (isConfidentialIssuance) {
              const assetCommitment = yield confidential$1.assetCommitment(
                token,
                blindingDataIssuance.assetBlindingFactor,
              );
              const valueCommitment = yield confidential$1.valueCommitment(
                tokenValue,
                assetCommitment,
                blindingDataIssuance.valueBlindingFactor,
              );
              const rangeProof = yield confidential$1.rangeProofWithoutNonceHash(
                tokenValue,
                issuanceBlindingPrivKeys[i].tokenKey,
                token,
                blindingDataIssuance.assetBlindingFactor,
                blindingDataIssuance.valueBlindingFactor,
                valueCommitment,
                Buffer$1.alloc(0),
                '1',
                0,
                52,
              );
              this.__CACHE.__TX.ins[i].inflationRangeProof = rangeProof;
              this.__CACHE.__TX.ins[i].issuance.tokenAmount = valueCommitment;
            }
          }
        }
        i++;
      }
      // get data (satoshis & asset) outputs to blind
      const outputsData = outputIndexes.map(index => {
        const output = c.__TX.outs[index];
        // prevent blinding the fee output
        if (output.script.length === 0)
          throw new Error("cant't blind the fee output");
        const value = confidential$1
          .confidentialValueToSatoshi(output.value)
          .toString(10);
        return [value, output.asset.slice(1)];
      });
      // compute the outputs blinders
      const outputsBlindingData = yield computeOutputsBlindingData(
        inputsBlindingData,
        outputsData,
      );
      // use blinders to compute proofs & commitments
      let indexInArray = 0;
      for (const outputIndex of outputIndexes) {
        const randomSeed = randomBytes(opts);
        const ephemeralPrivKey = randomBytes(opts);
        const outputNonce = ecpair.fromPrivateKey(ephemeralPrivKey).publicKey;
        const outputBlindingData = outputsBlindingData[indexInArray];
        // commitments
        const assetCommitment = yield confidential$1.assetCommitment(
          outputBlindingData.asset,
          outputBlindingData.assetBlindingFactor,
        );
        const valueCommitment = yield confidential$1.valueCommitment(
          outputBlindingData.value,
          assetCommitment,
          outputBlindingData.valueBlindingFactor,
        );
        // proofs
        const rangeProof = yield confidential$1.rangeProof(
          outputBlindingData.value,
          blindingPubkeys[indexInArray],
          ephemeralPrivKey,
          outputBlindingData.asset,
          outputBlindingData.assetBlindingFactor,
          outputBlindingData.valueBlindingFactor,
          valueCommitment,
          c.__TX.outs[outputIndex].script,
        );
        const surjectionProof = yield confidential$1.surjectionProof(
          outputBlindingData.asset,
          outputBlindingData.assetBlindingFactor,
          inputsBlindingData.map(({ asset }) => asset),
          inputsBlindingData.map(
            ({ assetBlindingFactor }) => assetBlindingFactor,
          ),
          randomSeed,
        );
        // set commitments & proofs & nonce
        c.__TX.outs[outputIndex].asset = assetCommitment;
        c.__TX.outs[outputIndex].value = valueCommitment;
        c.__TX.setOutputNonce(outputIndex, outputNonce);
        c.__TX.setOutputRangeProof(outputIndex, rangeProof);
        c.__TX.setOutputSurjectionProof(outputIndex, surjectionProof);
        indexInArray++;
      }
      c.__FEE = undefined;
      c.__FEE_RATE = undefined;
      c.__EXTRACTED_TX = undefined;
      return this;
    });
  }
}
var Psbt_1 = Psbt$1;
/**
 * This function is needed to pass to the bip174 base class's fromBuffer.
 * It takes the "transaction buffer" portion of the psbt buffer and returns a
 * Transaction (From the bip174 library) interface.
 */
const transactionFromBuffer = buffer => new PsbtTransaction(buffer);
/**
 * This class implements the Transaction interface from bip174 library.
 * It contains a liquidjs-lib Transaction object.
 */
class PsbtTransaction {
  constructor(buffer = Buffer$1.from([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])) {
    this.tx = transaction.Transaction.fromBuffer(buffer);
    checkTxEmpty(this.tx);
    Object.defineProperty(this, 'tx', {
      enumerable: false,
      writable: true,
    });
  }
  getInputOutputCounts() {
    return {
      inputCount: this.tx.ins.length,
      outputCount: this.tx.outs.length,
    };
  }
  addInput(input) {
    if (
      input.hash === undefined ||
      input.index === undefined ||
      (!Buffer$1.isBuffer(input.hash) && typeof input.hash !== 'string') ||
      typeof input.index !== 'number'
    ) {
      throw new Error('Error adding input.');
    }
    const hash =
      typeof input.hash === 'string'
        ? bufferutils$1.reverseBuffer(Buffer$1.from(input.hash, 'hex'))
        : input.hash;
    this.tx.addInput(hash, input.index, input.sequence);
  }
  addOutput(output) {
    if (
      output.script === undefined ||
      (!Buffer$1.isBuffer(output.script) && typeof output.script !== 'string') ||
      output.value === undefined ||
      (!Buffer$1.isBuffer(output.value) && typeof output.value !== 'number') ||
      output.asset === undefined ||
      (!Buffer$1.isBuffer(output.asset) && typeof output.asset !== 'string')
    ) {
      throw new Error('Error adding output.');
    }
    const nonce = Buffer$1.alloc(1, 0);
    const script = Buffer$1.isBuffer(output.script)
      ? output.script
      : Buffer$1.from(output.script, 'hex');
    const value = Buffer$1.isBuffer(output.value)
      ? output.value
      : confidential$1.satoshiToConfidentialValue(output.value);
    const asset = Buffer$1.isBuffer(output.asset)
      ? output.asset
      : Buffer$1.concat([
          Buffer$1.alloc(1, 1),
          bufferutils$1.reverseBuffer(Buffer$1.from(output.asset, 'hex')),
        ]);
    this.tx.addOutput(script, value, asset, nonce);
  }
  toBuffer() {
    return this.tx.toBuffer();
  }
}
function canFinalize(input, script, scriptType) {
  switch (scriptType) {
    case 'pubkey':
    case 'pubkeyhash':
    case 'witnesspubkeyhash':
      return hasSigs(1, input.partialSig);
    case 'multisig':
      const p2ms = payments$1.p2ms({ output: script });
      return hasSigs(p2ms.m, input.partialSig, p2ms.pubkeys);
    default:
      return false;
  }
}
function hasSigs(neededSigs, partialSig, pubkeys) {
  if (!partialSig) return false;
  let sigs;
  if (pubkeys) {
    sigs = pubkeys
      .map(pkey => {
        const pubkey = ecpair.fromPublicKey(pkey, { compressed: true })
          .publicKey;
        return partialSig.find(pSig => pSig.pubkey.equals(pubkey));
      })
      .filter(v => !!v);
  } else {
    sigs = partialSig;
  }
  if (sigs.length > neededSigs) throw new Error('Too many signatures');
  return sigs.length === neededSigs;
}
function isFinalized(input) {
  return !!input.finalScriptSig || !!input.finalScriptWitness;
}
function isPaymentFactory(payment) {
  return script => {
    try {
      payment({ output: script });
      return true;
    } catch (err) {
      return false;
    }
  };
}
const isP2MS = isPaymentFactory(payments$1.p2ms);
const isP2PK = isPaymentFactory(payments$1.p2pk);
const isP2PKH = isPaymentFactory(payments$1.p2pkh);
const isP2WPKH = isPaymentFactory(payments$1.p2wpkh);
const isP2WSHScript = isPaymentFactory(payments$1.p2wsh);
function check32Bit(num) {
  if (
    typeof num !== 'number' ||
    num !== Math.floor(num) ||
    num > 0xffffffff ||
    num < 0
  ) {
    throw new Error('Invalid 32 bit integer');
  }
}
function checkFees(psbt, cache, opts) {
  const feeRate = cache.__FEE_RATE || psbt.getFeeRate();
  const vsize = cache.__EXTRACTED_TX.virtualSize();
  const satoshis = feeRate * vsize;
  if (feeRate >= opts.maximumFeeRate) {
    throw new Error(
      `Warning: You are paying around ${(satoshis / 1e8).toFixed(8)} in ` +
        `fees, which is ${feeRate} satoshi per byte for a transaction ` +
        `with a VSize of ${vsize} bytes (segwit counted as 0.25 byte per ` +
        `byte). Use setMaximumFeeRate method to raise your threshold, or ` +
        `pass true to the first arg of extractTransaction.`,
    );
  }
}
function checkInputsForPartialSig(inputs, action) {
  inputs.forEach(input => {
    let throws = false;
    let pSigs = [];
    if ((input.partialSig || []).length === 0) {
      if (!input.finalScriptSig && !input.finalScriptWitness) return;
      pSigs = getPsigsFromInputFinalScripts(input);
    } else {
      pSigs = input.partialSig;
    }
    pSigs.forEach(pSig => {
      const { hashType } = bscript.signature.decode(pSig.signature);
      const whitelist = [];
      const isAnyoneCanPay =
        hashType & transaction.Transaction.SIGHASH_ANYONECANPAY;
      if (isAnyoneCanPay) whitelist.push('addInput');
      const hashMod = hashType & 0x1f;
      switch (hashMod) {
        case transaction.Transaction.SIGHASH_ALL:
          break;
        case transaction.Transaction.SIGHASH_SINGLE:
        case transaction.Transaction.SIGHASH_NONE:
          whitelist.push('addOutput');
          whitelist.push('setInputSequence');
          break;
      }
      if (whitelist.indexOf(action) === -1) {
        throws = true;
      }
    });
    if (throws) {
      throw new Error('Can not modify transaction, signatures exist.');
    }
  });
}
function checkPartialSigSighashes(input) {
  if (!input.sighashType || !input.partialSig) return;
  const { partialSig, sighashType } = input;
  partialSig.forEach(pSig => {
    const { hashType } = bscript.signature.decode(pSig.signature);
    if (sighashType !== hashType) {
      throw new Error('Signature sighash does not match input sighash type');
    }
  });
}
function checkScriptForPubkey(pubkey, script, action) {
  const pubkeyHash = crypto$2.hash160(pubkey);
  const decompiled = bscript.decompile(script);
  if (decompiled === null) throw new Error('Unknown script error');
  const hasKey = decompiled.some(element => {
    if (typeof element === 'number') return false;
    return element.equals(pubkey) || element.equals(pubkeyHash);
  });
  if (!hasKey) {
    throw new Error(
      `Can not ${action} for this input with the key ${pubkey.toString('hex')}`,
    );
  }
}
function checkTxEmpty(tx) {
  const isEmpty = tx.ins.every(
    input => input.script && input.script.length === 0,
  );
  if (!isEmpty) {
    throw new Error('Format Error: Transaction ScriptSigs are not empty');
  }
  // if (tx.flag === 1 && tx.witnessIn.length > 0) {
  //   throw new Error('Format Error: Transaction WitnessScriptSigs are not empty');
  // }
}
function checkTxForDupeIns(tx, cache) {
  tx.ins.forEach(input => {
    checkTxInputCache(cache, input);
  });
}
function checkTxInputCache(cache, input) {
  const key =
    bufferutils$1.reverseBuffer(Buffer$1.from(input.hash)).toString('hex') +
    ':' +
    input.index;
  if (cache.__TX_IN_CACHE[key]) throw new Error('Duplicate input detected.');
  cache.__TX_IN_CACHE[key] = 1;
}
function scriptCheckerFactory(payment, paymentScriptName) {
  return (inputIndex, scriptPubKey, redeemScript) => {
    const redeemScriptOutput = payment({
      redeem: { output: redeemScript },
    }).output;
    if (!scriptPubKey.equals(redeemScriptOutput)) {
      throw new Error(
        `${paymentScriptName} for input #${inputIndex} doesn't match the scriptPubKey in the prevout`,
      );
    }
  };
}
const checkRedeemScript = scriptCheckerFactory(payments$1.p2sh, 'Redeem script');
const checkWitnessScript = scriptCheckerFactory(
  payments$1.p2wsh,
  'Witness script',
);
function getTxCacheValue(key, name, inputs, c) {
  if (!inputs.every(isFinalized))
    throw new Error(`PSBT must be finalized to calculate ${name}`);
  if (key === '__FEE_RATE' && c.__FEE_RATE) return c.__FEE_RATE;
  if (key === '__FEE' && c.__FEE) return c.__FEE;
  let tx;
  let mustFinalize = true;
  if (c.__EXTRACTED_TX) {
    tx = c.__EXTRACTED_TX;
    mustFinalize = false;
  } else {
    tx = c.__TX.clone();
  }
  inputFinalizeGetAmts(inputs, tx, c, mustFinalize);
  if (key === '__FEE_RATE') return c.__FEE_RATE;
  else if (key === '__FEE') return c.__FEE;
}
function getFinalScripts(
  script,
  scriptType,
  partialSig,
  isSegwit,
  isP2SH,
  isP2WSH,
) {
  let finalScriptSig;
  let finalScriptWitness;
  // Wow, the payments API is very handy
  const payment = getPayment(script, scriptType, partialSig);
  const p2wsh = !isP2WSH ? null : payments$1.p2wsh({ redeem: payment });
  const p2sh = !isP2SH ? null : payments$1.p2sh({ redeem: p2wsh || payment });
  if (isSegwit) {
    if (p2wsh) {
      finalScriptWitness = witnessStackToScriptWitness(p2wsh.witness);
    } else {
      finalScriptWitness = witnessStackToScriptWitness(payment.witness);
    }
    if (p2sh) {
      finalScriptSig = p2sh.input;
    }
  } else {
    if (p2sh) {
      finalScriptSig = p2sh.input;
    } else {
      finalScriptSig = payment.input;
    }
  }
  return {
    finalScriptSig,
    finalScriptWitness,
  };
}
function getHashAndSighashType(
  inputs,
  inputIndex,
  pubkey,
  cache,
  sighashTypes,
) {
  const input = utils_1.checkForInput(inputs, inputIndex);
  const { hash, sighashType, script } = getHashForSig(
    inputIndex,
    input,
    cache,
    sighashTypes,
  );
  checkScriptForPubkey(pubkey, script, 'sign');
  return {
    hash,
    sighashType,
  };
}
function getHashForSig(inputIndex, input, cache, sighashTypes) {
  const unsignedTx = cache.__TX;
  const sighashType =
    input.sighashType || transaction.Transaction.SIGHASH_ALL;
  if (sighashTypes && sighashTypes.indexOf(sighashType) < 0) {
    const str = sighashTypeToString(sighashType);
    throw new Error(
      `Sighash type is not allowed. Retry the sign method passing the ` +
        `sighashTypes array of whitelisted types. Sighash type: ${str}`,
    );
  }
  let hash;
  let script;
  if (input.nonWitnessUtxo) {
    const nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(
      cache,
      input,
      inputIndex,
    );
    const prevoutHash = unsignedTx.ins[inputIndex].hash;
    const utxoHash = nonWitnessUtxoTx.getHash();
    // If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
    if (!prevoutHash.equals(utxoHash)) {
      throw new Error(
        `Non-witness UTXO hash for input #${inputIndex} doesn't match the hash specified in the prevout`,
      );
    }
    const prevoutIndex = unsignedTx.ins[inputIndex].index;
    const prevout = nonWitnessUtxoTx.outs[prevoutIndex];
    if (input.redeemScript) {
      // If a redeemScript is provided, the scriptPubKey must be for that redeemScript
      checkRedeemScript(inputIndex, prevout.script, input.redeemScript);
      script = input.redeemScript;
    } else {
      script = prevout.script;
    }
    if (isP2WSHScript(script)) {
      if (!input.witnessScript)
        throw new Error('Segwit input needs witnessScript if not P2WPKH');
      checkWitnessScript(inputIndex, script, input.witnessScript);
      hash = unsignedTx.hashForWitnessV0(
        inputIndex,
        input.witnessScript,
        prevout.value,
        sighashType,
      );
      script = input.witnessScript;
    } else if (isP2WPKH(script)) {
      // P2WPKH uses the P2PKH template for prevoutScript when signing
      const signingScript = payments$1.p2pkh({ hash: script.slice(2) }).output;
      hash = unsignedTx.hashForWitnessV0(
        inputIndex,
        signingScript,
        prevout.value,
        sighashType,
      );
    } else {
      hash = unsignedTx.hashForSignature(inputIndex, script, sighashType);
    }
  } else if (input.witnessUtxo) {
    let _script; // so we don't shadow the `let script` above
    if (input.redeemScript) {
      // If a redeemScript is provided, the scriptPubKey must be for that redeemScript
      checkRedeemScript(
        inputIndex,
        input.witnessUtxo.script,
        input.redeemScript,
      );
      _script = input.redeemScript;
    } else {
      _script = input.witnessUtxo.script;
    }
    if (isP2WPKH(_script)) {
      // P2WPKH uses the P2PKH template for prevoutScript when signing
      const signingScript = payments$1.p2pkh({ hash: _script.slice(2) }).output;
      hash = unsignedTx.hashForWitnessV0(
        inputIndex,
        signingScript,
        input.witnessUtxo.value,
        sighashType,
      );
      script = _script;
    } else if (isP2WSHScript(_script)) {
      if (!input.witnessScript)
        throw new Error('Segwit input needs witnessScript if not P2WPKH');
      checkWitnessScript(inputIndex, _script, input.witnessScript);
      hash = unsignedTx.hashForWitnessV0(
        inputIndex,
        input.witnessScript,
        input.witnessUtxo.value,
        sighashType,
      );
      // want to make sure the script we return is the actual meaningful script
      script = input.witnessScript;
    } else {
      throw new Error(
        `Input #${inputIndex} has witnessUtxo but non-segwit script: ` +
          `${_script.toString('hex')}`,
      );
    }
  } else {
    throw new Error('Need a Utxo input item for signing');
  }
  return {
    script,
    sighashType,
    hash,
  };
}
function getPayment(script, scriptType, partialSig) {
  let payment;
  switch (scriptType) {
    case 'multisig':
      const sigs = getSortedSigs(script, partialSig);
      payment = payments$1.p2ms({
        output: script,
        signatures: sigs,
      });
      break;
    case 'pubkey':
      payment = payments$1.p2pk({
        output: script,
        signature: partialSig[0].signature,
      });
      break;
    case 'pubkeyhash':
      payment = payments$1.p2pkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
      break;
    case 'witnesspubkeyhash':
      payment = payments$1.p2wpkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
      break;
  }
  return payment;
}
function getPsigsFromInputFinalScripts(input) {
  const scriptItems = !input.finalScriptSig
    ? []
    : bscript.decompile(input.finalScriptSig) || [];
  const witnessItems = !input.finalScriptWitness
    ? []
    : bscript.decompile(input.finalScriptWitness) || [];
  return scriptItems
    .concat(witnessItems)
    .filter(item => {
      return Buffer$1.isBuffer(item) && bscript.isCanonicalScriptSignature(item);
    })
    .map(sig => ({ signature: sig }));
}
function getScriptFromInput(inputIndex, input, cache) {
  const unsignedTx = cache.__TX;
  const res = {
    script: null,
    isSegwit: false,
    isP2SH: false,
    isP2WSH: false,
  };
  res.isP2SH = !!input.redeemScript;
  res.isP2WSH = !!input.witnessScript;
  if (input.witnessScript) {
    res.script = input.witnessScript;
  } else if (input.redeemScript) {
    res.script = input.redeemScript;
  } else {
    if (input.nonWitnessUtxo) {
      const nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(
        cache,
        input,
        inputIndex,
      );
      const prevoutIndex = unsignedTx.ins[inputIndex].index;
      res.script = nonWitnessUtxoTx.outs[prevoutIndex].script;
    } else if (input.witnessUtxo) {
      res.script = input.witnessUtxo.script;
    }
  }
  if (input.witnessScript || isP2WPKH(res.script)) {
    res.isSegwit = true;
  }
  return res;
}
function getSignersFromHD(inputIndex, inputs, hdKeyPair) {
  const input = utils_1.checkForInput(inputs, inputIndex);
  if (!input.bip32Derivation || input.bip32Derivation.length === 0) {
    throw new Error('Need bip32Derivation to sign with HD');
  }
  const myDerivations = input.bip32Derivation
    .map(bipDv => {
      if (bipDv.masterFingerprint.equals(hdKeyPair.fingerprint)) {
        return bipDv;
      } else {
        return;
      }
    })
    .filter(v => !!v);
  if (myDerivations.length === 0) {
    throw new Error(
      'Need one bip32Derivation masterFingerprint to match the HDSigner fingerprint',
    );
  }
  const signers = myDerivations.map(bipDv => {
    const node = hdKeyPair.derivePath(bipDv.path);
    if (!bipDv.pubkey.equals(node.publicKey)) {
      throw new Error('pubkey did not match bip32Derivation');
    }
    return node;
  });
  return signers;
}
function getSortedSigs(script, partialSig) {
  const p2ms = payments$1.p2ms({ output: script });
  // for each pubkey in order of p2ms script
  return p2ms.pubkeys
    .map(pk => {
      // filter partialSig array by pubkey being equal
      return (
        partialSig.filter(ps => {
          return ps.pubkey.equals(pk);
        })[0] || {}
      ).signature;
      // Any pubkey without a match will return undefined
      // this last filter removes all the undefined items in the array.
    })
    .filter(v => !!v);
}
function scriptWitnessToWitnessStack(buffer) {
  let offset = 0;
  function readSlice(n) {
    offset += n;
    return buffer.slice(offset - n, offset);
  }
  function readVarInt() {
    const vi = varuint.decode(buffer, offset);
    offset += varuint.decode.bytes;
    return vi;
  }
  function readVarSlice() {
    return readSlice(readVarInt());
  }
  function readVector() {
    const count = readVarInt();
    const vector = [];
    for (let i = 0; i < count; i++) vector.push(readVarSlice());
    return vector;
  }
  return readVector();
}
function sighashTypeToString(sighashType) {
  let text =
    sighashType & transaction.Transaction.SIGHASH_ANYONECANPAY
      ? 'SIGHASH_ANYONECANPAY | '
      : '';
  const sigMod = sighashType & 0x1f;
  switch (sigMod) {
    case transaction.Transaction.SIGHASH_ALL:
      text += 'SIGHASH_ALL';
      break;
    case transaction.Transaction.SIGHASH_SINGLE:
      text += 'SIGHASH_SINGLE';
      break;
    case transaction.Transaction.SIGHASH_NONE:
      text += 'SIGHASH_NONE';
      break;
  }
  return text;
}
function witnessStackToScriptWitness(witness) {
  let buffer = Buffer$1.allocUnsafe(0);
  function writeSlice(slice) {
    buffer = Buffer$1.concat([buffer, Buffer$1.from(slice)]);
  }
  function writeVarInt(i) {
    const currentLen = buffer.length;
    const varintLen = varuint.encodingLength(i);
    buffer = Buffer$1.concat([buffer, Buffer$1.allocUnsafe(varintLen)]);
    varuint.encode(i, buffer, currentLen);
  }
  function writeVarSlice(slice) {
    writeVarInt(slice.length);
    writeSlice(slice);
  }
  function writeVector(vector) {
    writeVarInt(vector.length);
    vector.forEach(writeVarSlice);
  }
  writeVector(witness);
  return buffer;
}
function addNonWitnessTxCache(cache, input, inputIndex) {
  cache.__NON_WITNESS_UTXO_BUF_CACHE[inputIndex] = input.nonWitnessUtxo;
  const tx = transaction.Transaction.fromBuffer(input.nonWitnessUtxo);
  cache.__NON_WITNESS_UTXO_TX_CACHE[inputIndex] = tx;
  const self = cache;
  const selfIndex = inputIndex;
  delete input.nonWitnessUtxo;
  Object.defineProperty(input, 'nonWitnessUtxo', {
    enumerable: true,
    get() {
      const buf = self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex];
      const txCache = self.__NON_WITNESS_UTXO_TX_CACHE[selfIndex];
      if (buf !== undefined) {
        return buf;
      } else {
        const newBuf = txCache.toBuffer();
        self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex] = newBuf;
        return newBuf;
      }
    },
    set(data) {
      self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex] = data;
    },
  });
}
function inputFinalizeGetAmts(inputs, tx, cache, mustFinalize) {
  inputs.forEach((input, idx) => {
    if (mustFinalize && input.finalScriptSig)
      tx.ins[idx].script = input.finalScriptSig;
    if (mustFinalize && input.finalScriptWitness) {
      tx.ins[idx].witness = scriptWitnessToWitnessStack(
        input.finalScriptWitness,
      );
    }
  });
  if (tx.ins.some(x => x.witness.length !== 0)) {
    tx.flag = 1;
  }
  const bytes = tx.virtualSize();
  const fee = 2 * bytes;
  cache.__FEE = fee;
  cache.__EXTRACTED_TX = tx;
  cache.__FEE_RATE = Math.floor(fee / bytes);
}
function nonWitnessUtxoTxFromCache(cache, input, inputIndex) {
  const c = cache.__NON_WITNESS_UTXO_TX_CACHE;
  if (!c[inputIndex]) {
    addNonWitnessTxCache(cache, input, inputIndex);
  }
  return c[inputIndex];
}
function classifyScript(script) {
  if (isP2WPKH(script)) return 'witnesspubkeyhash';
  if (isP2PKH(script)) return 'pubkeyhash';
  if (isP2MS(script)) return 'multisig';
  if (isP2PK(script)) return 'pubkey';
  return 'nonstandard';
}
function range(n) {
  return [...Array(n).keys()];
}
function randomBytes(options) {
  if (options === undefined) options = {};
  const rng = options.rng || randomBytes$1;
  return rng(32);
}
/**
 * Compute outputs blinders
 * @param inputsBlindingData the transaction inputs blinding data
 * @param outputsData data = [satoshis, asset] of output to blind ([string Buffer])
 * @returns an array of BlindingData[] corresponding of blinders to blind outputs specified in outputsData
 */
function computeOutputsBlindingData(inputsBlindingData, outputsData) {
  return __awaiter(this, void 0, void 0, function*() {
    const outputsBlindingData = [];
    outputsData
      .slice(0, outputsData.length - 1)
      .forEach(([satoshis, asset]) => {
        const blindingData = {
          value: satoshis,
          asset,
          valueBlindingFactor: randomBytes(),
          assetBlindingFactor: randomBytes(),
        };
        outputsBlindingData.push(blindingData);
      });
    const [lastOutputValue, lastOutputAsset] = outputsData[
      outputsData.length - 1
    ];
    const finalBlindingData = {
      value: lastOutputValue,
      asset: lastOutputAsset,
      assetBlindingFactor: randomBytes(),
      valueBlindingFactor: Buffer$1.from([]),
    };
    // values
    const inputsValues = inputsBlindingData.map(({ value }) => value);
    const outputsValues = outputsData
      .map(([amount]) => amount)
      .concat(lastOutputValue);
    // asset blinders
    const inputsAssetBlinders = inputsBlindingData.map(
      ({ assetBlindingFactor }) => assetBlindingFactor,
    );
    const outputsAssetBlinders = outputsBlindingData
      .map(({ assetBlindingFactor }) => assetBlindingFactor)
      .concat(finalBlindingData.assetBlindingFactor);
    // value blinders
    const inputsAmountBlinders = inputsBlindingData.map(
      ({ valueBlindingFactor }) => valueBlindingFactor,
    );
    const outputsAmountBlinders = outputsBlindingData.map(
      ({ valueBlindingFactor }) => valueBlindingFactor,
    );
    // compute output final amount blinder
    const finalAmountBlinder = yield confidential$1.valueBlindingFactor(
      inputsValues,
      outputsValues,
      inputsAssetBlinders,
      outputsAssetBlinders,
      inputsAmountBlinders,
      outputsAmountBlinders,
    );
    finalBlindingData.valueBlindingFactor = finalAmountBlinder;
    outputsBlindingData.push(finalBlindingData);
    return outputsBlindingData;
  });
}
var computeOutputsBlindingData_1 = computeOutputsBlindingData;
/**
 * toBlindingData convert a BlindingDataLike to UnblindOutputResult
 * @param blindDataLike blinding data "like" associated to a specific input I
 * @param witnessUtxo the prevout of the input I
 */
function toBlindingData(blindDataLike, witnessUtxo) {
  return __awaiter(this, void 0, void 0, function*() {
    if (!blindDataLike) {
      if (!witnessUtxo) throw new Error('need witnessUtxo');
      return getUnconfidentialWitnessUtxoBlindingData(witnessUtxo);
    }
    if (Buffer$1.isBuffer(blindDataLike)) {
      if (!witnessUtxo) throw new Error('need witnessUtxo');
      return confidential$1.unblindOutputWithKey(witnessUtxo, blindDataLike);
    }
    return blindDataLike;
  });
}
var toBlindingData_1 = toBlindingData;
function getUnconfidentialWitnessUtxoBlindingData(prevout) {
  const unblindedInputBlindingData = {
    value: confidential$1.confidentialValueToSatoshi(prevout.value).toString(10),
    valueBlindingFactor: transaction.ZERO,
    asset: prevout.asset.slice(1),
    assetBlindingFactor: transaction.ZERO,
  };
  return unblindedInputBlindingData;
}

var psbt = /*#__PURE__*/Object.defineProperty({
	Psbt: Psbt_1,
	computeOutputsBlindingData: computeOutputsBlindingData_1,
	toBlindingData: toBlindingData_1
}, '__esModule', {value: true});

var __importStar =
  (commonjsGlobal && commonjsGlobal.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };

const bip32 = __importStar(require$$0);
var bip32_1 = bip32;
const address = __importStar(address$1);
var address_1 = address;
const confidential = __importStar(confidential$2);
var confidential_1 = confidential;
const crypto = __importStar(crypto$2);
var crypto_1 = crypto;
const ECPair = __importStar(ecpair);
var ECPair_1 = ECPair;
const networks = __importStar(networks$2);
var networks_1 = networks;
const payments = __importStar(payments$3);
var payments_1 = payments;
const script = __importStar(script$1);
var script_2 = script;

var Block = block.Block;

var Psbt = psbt.Psbt;

var opcodes = script$1.OPS;

var Transaction = transaction.Transaction;

var src = /*#__PURE__*/Object.defineProperty({
	bip32: bip32_1,
	address: address_1,
	confidential: confidential_1,
	crypto: crypto_1,
	ECPair: ECPair_1,
	networks: networks_1,
	payments: payments_1,
	script: script_2,
	Block: Block,
	Psbt: Psbt,
	opcodes: opcodes,
	Transaction: Transaction
}, '__esModule', {value: true});

export default src;
export { Block, ECPair_1 as ECPair, Psbt, Transaction, address_1 as address, bip32_1 as bip32, confidential_1 as confidential, crypto_1 as crypto, networks_1 as networks, opcodes, payments_1 as payments, script_2 as script };
