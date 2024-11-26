control 'SV-55764' do
  title 'The IP-based VTC system must use H.235-based signaling encryption.'
  desc 'An IP/H.323-based VTC system as a whole (including CODECs, MCUs, Gatekeepers, Gateways, firewall traversal border elements, etc.) must implement H.235-based signaling encryption. H.235 has been developed to help secure the signaling protocols used in the H.323 suite of protocols. H.235 uses the Advanced Encryption Standard (AES) for encryption and the Diffie-Hellman key exchange protocol for key exchange. AES is supported under H.235 version 3. Technical details of H.235 are set forth in the ITU-T Recommendation H.235.6 (2005), H.323 security: Voice encryption profile with native H.235/H.245 key management.'
  desc 'check', 'Review the documentation to determine that the VTC equipment supports H.235-based signaling encryption and review configuration of the equipment to verify that it is being implemented. If the equipment does not support H.235-based signaling encryption or it has not been implemented, this is a finding.'
  desc 'fix', 'Obtain equipment that supports H.235-based signaling encryption and configure the equipment to implement encryption.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49187r3_chk'
  tag severity: 'medium'
  tag gid: 'V-43035'
  tag rid: 'SV-55764r1_rule'
  tag stig_id: 'RTS-VTC 1240'
  tag gtitle: 'RTS-VTC 1240 [IP]'
  tag fix_id: 'F-48617r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECCT-1, ECNK-1, ECSC-1'
end
