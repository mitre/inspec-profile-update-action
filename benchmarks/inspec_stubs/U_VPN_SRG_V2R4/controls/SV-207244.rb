control 'SV-207244' do
  title 'The IPsec VPN Gateway must specify Perfect Forward Secrecy (PFS) during Internet Key Exchange (IKE) negotiation.'
  desc 'PFS generates each new encryption key independently from the previous key. Without PFS, compromise of one key will compromise all communications.

The phase 2 (Quick Mode) Security Association (SA) is used to create an IPsec session key. Hence, its rekey or key regeneration procedure is very important. The phase 2 rekey can be performed with or without Perfect Forward Secrecy (PFS). With PFS, every time a new IPsec Security Association is negotiated during the Quick Mode, a new Diffie-Hellman (DH) exchange occurs. The new DH shared secret will be included with original keying material (SYKEID_d, initiator nonce, and responder nonce from phase 1 for generating a new IPsec session key. If PFS is not used, the IPsec session key will always be completely dependent on the original keying material from the Phase-1. Hence, if an older key is compromised at any time, it is possible that all new keys may be compromised.

The DH exchange is performed in the same manner as was done in phase 1 (Main or Aggressive Mode). However, the phase 2 exchange is protected by encrypting the phase 2 packets with the key derived from the phase 1 negotiation. Because DH negotiations during phase 2 are encrypted, the new IPsec session key has an added element of secrecy.'
  desc 'check', 'Verify the IPsec VPN Gateway specifies Perfect Forward Secrecy (PFS) during Internet Key Exchange (IKE) negotiation.

If the IPsec VPN Gateway does not specify Perfect Forward Secrecy (PFS) during Internet Key Exchange (IKE) negotiation, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway to specify Perfect Forward Secrecy (PFS) during Internet Key Exchange (IKE) negotiation.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7504r378353_chk'
  tag severity: 'medium'
  tag gid: 'V-207244'
  tag rid: 'SV-207244r608988_rule'
  tag stig_id: 'SRG-NET-000371-VPN-001640'
  tag gtitle: 'SRG-NET-000371'
  tag fix_id: 'F-7504r378354_fix'
  tag 'documentable'
  tag legacy: ['SV-106321', 'V-97183']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
