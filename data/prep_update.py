# Builds the guest input for one light-client update: committee keys, bits, signature, signing root.
import json, hashlib, sys
def h(a,b): return hashlib.sha256(a+b).digest()
def merkleize(chunks):
    n=1
    while n<len(chunks): n*=2
    chunks=chunks+[b'\0'*32]*(n-len(chunks))
    while len(chunks)>1: chunks=[h(chunks[i],chunks[i+1]) for i in range(0,len(chunks),2)]
    return chunks[0]
def u64(x): return int(x).to_bytes(8,'little')+b'\0'*24
def root(hx): return bytes.fromhex(hx[2:])
spec=json.load(open('spec.json'))['data']; gvr=root(json.load(open('genesis.json'))['data']['genesis_validators_root'])
ups=[u['data'] for u in json.load(open(sys.argv[1]))]
prev, cur = ups[0], ups[1]
keys=[k for k in prev['next_sync_committee']['pubkeys']]
att=cur['attested_header']['beacon']
hdr_root=merkleize([u64(att['slot']),u64(att['proposer_index']),root(att['parent_root']),root(att['state_root']),root(att['body_root'])])
sig_slot=int(cur['signature_slot']); epoch=sig_slot//int(spec['SLOTS_PER_EPOCH'])
forks=sorted([(int(spec[k.replace('VERSION','EPOCH')]),bytes.fromhex(spec[k][2:])) for k in spec if k.endswith('_FORK_VERSION') and k.replace('VERSION','EPOCH') in spec and int(spec[k.replace('VERSION','EPOCH')])<2**60])
version=[v for e,v in forks if e<=epoch][-1]
fork_data_root=merkleize([version+b'\0'*28, gvr])
domain=bytes.fromhex(spec['DOMAIN_SYNC_COMMITTEE'][2:])+fork_data_root[:28]
signing_root=merkleize([hdr_root, domain])
bits=bytes.fromhex(cur['sync_aggregate']['sync_committee_bits'][2:])
part=[i for i in range(512) if (bits[i//8]>>(i%8))&1]
out={'attested_slot':int(att['slot']),'signature_slot':sig_slot,'fork_version':version.hex(),'header_root':hdr_root.hex(),'signing_root':signing_root.hex(),
     'pubkeys':[k[2:] for k in keys],'bits':bits.hex(),'signature':cur['sync_aggregate']['sync_committee_signature'][2:],'participants':len(part),
     'absent':[i for i in range(512) if i not in part]}
json.dump(out,open(sys.argv[2],'w'))
print('attested_slot',out['attested_slot'],'signature_slot',sig_slot,'epoch',epoch,'fork_version',version.hex(),'participants',len(part),'absent',out['absent'],'signing_root',signing_root.hex()[:16])
