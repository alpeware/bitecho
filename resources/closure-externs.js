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
