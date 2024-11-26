control 'SV-214680' do
  title 'The Juniper SRX Services Gateway VPN must specify Perfect Forward Secrecy (PFS).'
  desc 'PFS generates each new encryption key independently from the previous key. Without PFS, compromise of one key will compromise all communications. 

The phase 2 (Quick Mode) Security Association (SA) is used to create an IPsec session key. Hence, its rekey or key regeneration procedure is very important. The phase 2 rekey can be performed with or without Perfect Forward Secrecy (PFS). With PFS, every time a new IPsec Security Association is negotiated during the Quick Mode, a new Diffie-Hellman (DH) exchange occurs. The new DH shared secret will be included with original keying material (SYKEID_d, initiator nonce, and responder nonce from phase 1) for generating a new IPsec session key. If PFS is not used, the IPsec session key will always be completely dependent on the original keying material from the Phase-1. Hence, if an older key is compromised at any time, it is possible that all new keys may be compromised. 

The DH exchange is performed in the same manner as was done in phase 1 (Main or Aggressive Mode). However, the phase 2 exchange is protected by encrypting the phase 2 packets with the key derived from the phase 1 negotiation. Because DH negotiations during phase 2 are encrypted, the new IPsec session key has an added element of secrecy.'
  desc 'check', 'Examine all IPsec profiles to verify PFS is enabled.

[edit]
show security ipsec policy

If PFS is not configured, this is a finding.'
  desc 'fix', 'Configure the VPN gateway to ensure PFS is enabled. The following commands configure an IPsec policy, enabling PFS using Diffie-Hellman group 14 and associates the IPsec proposal configured in the previous example.

[edit]
set security ipsec policy <IPSEC-POLICY> perfect-forward-secrecy keys group14
set security ipsec policy <IPSEC-POLICY> proposals <IPSEC-PROPOSAL>'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15881r297627_chk'
  tag severity: 'medium'
  tag gid: 'V-214680'
  tag rid: 'SV-214680r385561_rule'
  tag stig_id: 'JUSX-VN-000013'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-15879r297628_fix'
  tag 'documentable'
  tag legacy: ['V-66655', 'SV-81145']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
