control 'SV-239954' do
  title 'The Cisco ASA must be configured to specify Perfect Forward Secrecy (PFS) for the IPsec Security Association (SA) during IKE Phase 2 negotiation.'
  desc 'PFS generates each new encryption key independently from the previous key. Without PFS, compromise of one key will compromise all communications.

The Phase 2 (Quick Mode) Security Association (SA) is used to create an IPsec session key. Hence, its rekey or key regeneration procedure is very important. The Phase 2 rekey can be performed with or without Perfect Forward Secrecy (PFS). With PFS, every time a new IPsec Security Association is negotiated during the Quick Mode, a new Diffie-Hellman (DH) exchange occurs. The new DH shared secret will be included with original keying material (SYKEID_d, initiator nonce, and responder nonce from Phase 1 for generating a new IPsec session key. If PFS is not used, the IPsec session key will always be completely dependent on the original keying material from Phase 1. Hence, if an older key is compromised at any time, it is possible that all new keys may be compromised.

The DH exchange is performed in the same manner as was done in Phase 1 (Main or Aggressive Mode). However, the Phase 2 exchange is protected by encrypting the Phase 2 packets with the key derived from the Phase 1 negotiation. Because DH negotiations during Phase 2 are encrypted, the new IPsec session key has an added element of secrecy.'
  desc 'check', 'Review crypto maps that reference an IPsec proposal. Verify the ASA is configured to specify PFS as shown in the example below.

crypto map IPSEC_CRYPTO_MAP 1 set pfs group5
crypto map IPSEC_CRYPTO_MAP 1 set peer x.x.x.x 
crypto map IPSEC_CRYPTO_MAP 1 set ikev2 ipsec-proposal IPSEC_TRANS

If the ASA is not configured to specify PFS for the IPsec SA during IKE Phase 2 negotiation, this is a finding.'
  desc 'fix', 'Configure the ASA to specify PFS for the IPsec SA during IKE Phase 2 negotiation as shown in the example below.

ASA3(config)# crypto map IPSEC_CRYPTO_MAP 1 set pfs group5'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43187r666266_chk'
  tag severity: 'medium'
  tag gid: 'V-239954'
  tag rid: 'SV-239954r666268_rule'
  tag stig_id: 'CASA-VN-000180'
  tag gtitle: 'SRG-NET-000371-VPN-001640'
  tag fix_id: 'F-43146r666267_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
