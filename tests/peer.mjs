// Test peer for rlpx_client. Run with:  npm i @ethereumjs/devp2p @ethereumjs/util @ethereumjs/common && node tests/peer.mjs
// Test peer: an RLPx listener built on @ethereumjs/devp2p (independent implementation)
import { RLPx, ETH } from '@ethereumjs/devp2p';
import { hexToBytes, bytesToHex } from '@ethereumjs/util';
import { Common, Mainnet } from '@ethereumjs/common';

const PRIV = hexToBytes('0x' + 'a1'.repeat(32));
const rlpx = new RLPx(PRIV, {
  maxPeers: 10,
  capabilities: [ETH.eth68],
  common: new Common({ chain: Mainnet }),
  listenPort: 30303,
  clientId: new TextEncoder().encode('ethereumjs-test-peer/1.0'),
});
console.log('peer node id:', bytesToHex(rlpx.id));
rlpx.events.on('peer:added', (peer) => {
  const h = peer.getHelloMessage();
  console.log(`PEER ADDED: client=${h.clientId} p2p=${h.protocolVersion} caps=${h.capabilities.map(c=>c.name+'/'+c.version).join(',')}`);
  const eth = peer.getProtocols()[0];
  eth.sendStatus({
    td: new Uint8Array([0x01]), bestHash: new Uint8Array(32), genesisHash: new Uint8Array(32),
    latestBlock: new Uint8Array([0x01]), forkId: [new Uint8Array(4), new Uint8Array([0])],
  });
  eth.events.on('message', (code, payload) => console.log('eth message code', code));
});
rlpx.events.on('peer:removed', (peer, reason, we) => console.log('PEER REMOVED reason', reason, 'by us?', we));
rlpx.events.on('peer:error', (peer, err) => console.log('PEER ERROR', err.message));
rlpx.events.on('error', (err) => console.log('ERROR', err.message));
rlpx.listen(30303, '127.0.0.1');
console.log('listening on 127.0.0.1:30303');
