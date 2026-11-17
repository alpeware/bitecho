/**
 * @fileoverview Closure Compiler externs for Node.js and Browser APIs.
 * @externs
 */

var BitechoBrowser = {};
BitechoBrowser.initNode = function() {};
BitechoBrowser.ctl = function() {};
BitechoBrowser.execCommand = function() {};
BitechoBrowser.getSupportedVerbs = function() {};
BitechoBrowser.getState = function() {};
BitechoBrowser.getStatus = function() {};
BitechoBrowser.stopNode = function() {};
BitechoBrowser.connect = function() {};
BitechoBrowser.connectMesh = function() {};
BitechoBrowser.openChannel = function() {};
BitechoBrowser.acceptChannelOffer = function() {};
BitechoBrowser.p2pOffer = function() {};
BitechoBrowser.p2pAnswer = function() {};
BitechoBrowser.setP2pChannelState = function() {};
BitechoBrowser.broadcastMessage = function() {};
BitechoBrowser.sendMessage = function() {};
BitechoBrowser.closeSession = function() {};
BitechoBrowser.getChatHistory = function() {};
BitechoBrowser.getSessions = function() {};
BitechoBrowser.resolvePeer = function() {};
BitechoBrowser.onStateChange = function() {};
BitechoBrowser.handleVisibilityChange = function() {};
BitechoBrowser.saveStateToIndexedDB = function() {};
BitechoBrowser.loadStateFromIndexedDB = function() {};
BitechoBrowser.loadStateFromIndexedDb = function() {};
BitechoBrowser.restoreFromIndexedDB = function() {};
BitechoBrowser.restoreFromIndexedDb = function() {};
BitechoBrowser.createOffer = function() {};
BitechoBrowser.acceptOffer = function() {};
BitechoBrowser.sendSealedMessage = function() {};
BitechoBrowser.runSubnetDemo = function() {};
BitechoBrowser.runZeroBurnSubnetDemo = function() {};
BitechoBrowser.runFederationDemo = function() {};
BitechoBrowser.runThreeWayP2pBroadcastDemo = function() {};
BitechoBrowser.initAnchor = function() {};
BitechoBrowser.getAnchorDashboard = function() {};
BitechoBrowser.registerYubiKey = function() {};
BitechoBrowser.recoverFromYubiKey = function() {};
BitechoBrowser.createDiscoverableCredential = function() {};
BitechoBrowser.getDiscoverableCredential = function() {};
BitechoBrowser.queueOffer = function() {};
BitechoBrowser.generateNonExtractableKey = function() {};
BitechoBrowser.approveOffer = function() {};
BitechoBrowser.denyOffer = function() {};
BitechoBrowser.superviseAgent = function() {};
BitechoBrowser.revokeAgentDac = function() {};
BitechoBrowser.encodeBech32m = function() {};
BitechoBrowser.decodeBech32m = function() {};
BitechoBrowser.runAnchorEndToEndDemo = function() {};
BitechoBrowser.submitRelayEnvelope = function() {};
BitechoBrowser.pollRelayEnvelopes = function() {};
BitechoBrowser.ackRelayEnvelopes = function() {};
BitechoBrowser.fetchRelayChainState = function() {};
BitechoBrowser.version = "";

var nodeCrypto = {};
nodeCrypto.generateKeyPairSync = function(type, opts) {};
nodeCrypto.randomBytes = function(n) {};
nodeCrypto.createPrivateKey = function(opts) {};
nodeCrypto.createPublicKey = function(opts) {};
nodeCrypto.sign = function(algo, data, key) {};
nodeCrypto.verify = function(algo, data, key, sig) {};
nodeCrypto.diffieHellman = function(opts) {};
nodeCrypto.createCipheriv = function(algo, key, iv, opts) {};
nodeCrypto.createDecipheriv = function(algo, key, iv, opts) {};

var KeyObject = {};
KeyObject.export = function(opts) {};
KeyObject.publicKey = {};
KeyObject.privateKey = {};

var Cipher = {};
Cipher.setAAD = function(aad) {};
Cipher.getAuthTag = function() {};
Cipher.setAuthTag = function(tag) {};
Cipher.update = function(data) {};
Cipher.final = function() {};

var NodeExterns = {
  publicKeyEncoding: {},
  privateKeyEncoding: {},
  type: "",
  format: "",
  key: {},
  privateKey: {},
  publicKey: {},
  namedCurve: "",
  authTagLength: 0,
  saltLength: 0,
  padding: 0,
  constants: { RSA_PKCS1_PSS_PADDING: 0 },
  reuseAddr: true,
  recursive: true,
  mode: 0,
  encoding: "",
  stdio: "",
  detached: true,
  input: {},
  crlfDelay: 0,
  terminal: false,
  protocol: "",
  hostname: "",
  port: 0,
  path: "",
  pathname: "",
  search: "",
  method: "",
  timeout: 0,
  headers: {},
  createConnection: function() {},
  socket: {},
  servername: "",
  envelope_hex: "",
  statusCode: 0,
  remoteAddress: "",
  remotePort: 0,
  address: "",
  family: "",
  internal: false,
  size: 0,
  pid: 0,
  env: {},
  argv: [],
  execPath: "",
  stdin: {},
  stdout: {},
  stderr: {},
  Buffer: {}
};
NodeExterns.appendFileSync = function() {};
NodeExterns.chmodSync = function() {};
NodeExterns.closeSync = function() {};
NodeExterns.existsSync = function() {};
NodeExterns.fsyncSync = function() {};
NodeExterns.mkdirSync = function() {};
NodeExterns.openSync = function() {};
NodeExterns.readFileSync = function() {};
NodeExterns.readSync = function() {};
NodeExterns.renameSync = function() {};
NodeExterns.statSync = function() {};
NodeExterns.unlinkSync = function() {};
NodeExterns.writeFileSync = function() {};
NodeExterns.writeSync = function() {};
NodeExterns.dirname = function() {};
NodeExterns.join = function() {};
NodeExterns.homedir = function() {};
NodeExterns.networkInterfaces = function() {};
NodeExterns.createServer = function() {};
NodeExterns.createSocket = function() {};
NodeExterns.createInterface = function() {};
NodeExterns.createHash = function() {};
NodeExterns.createHmac = function() {};
NodeExterns.createECDH = function() {};
NodeExterns.computeSecret = function() {};
NodeExterns.generateKeys = function() {};
NodeExterns.getPublicKey = function() {};
NodeExterns.getPrivateKey = function() {};
NodeExterns.digest = function() {};
NodeExterns.request = function() {};
NodeExterns.get = function() {};
NodeExterns.connect = function() {};
NodeExterns.listen = function() {};
NodeExterns.bind = function() {};
NodeExterns.send = function() {};
NodeExterns.write = function() {};
NodeExterns.writeHead = function() {};
NodeExterns.end = function() {};
NodeExterns.destroy = function() {};
NodeExterns.resume = function() {};
NodeExterns.close = function() {};
NodeExterns.unref = function() {};
NodeExterns.kill = function() {};
NodeExterns.spawn = function() {};
NodeExterns.setNoDelay = function() {};
NodeExterns.addMembership = function() {};
NodeExterns.readUInt8 = function() {};
NodeExterns.readUInt16BE = function() {};
NodeExterns.readUIntBE = function() {};
NodeExterns.writeUInt8 = function() {};
NodeExterns.writeUInt16BE = function() {};
NodeExterns.writeUIntBE = function() {};
NodeExterns.subarray = function() {};
NodeExterns.copy = function() {};
NodeExterns.equals = function() {};
NodeExterns.concat = function() {};
NodeExterns.alloc = function() {};
NodeExterns.from = function() {};
