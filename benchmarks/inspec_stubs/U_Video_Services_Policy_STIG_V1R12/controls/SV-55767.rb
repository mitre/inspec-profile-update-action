control 'SV-55767' do
  title 'The operator of an ISDN-based VTC system utilizing a Type 1 encryptor for classified sessions must ensure any removable Keying Material (KEYMAT) (e.g., Cryptographic Ignition Key (CIK)) for the encryptor is secured in an appropriate secure facility or GSA-approved container when the system is not in use.'
  desc 'Removable Keying Material (KEYMAT) and each CIK must be handled in accordance with the Operational Security Doctrine of the encryptor as well as all applicable policies and guidance, such as the National Security Telecommunications and Information Systems Security Instruction 4000 series policies. When the CIK is not in use, it must be stored so that unauthorized personnel are unable to access it. This may mean that it is kept in a safe or in a locked desk behind a locked door to which only authorized personnel have access. The CIK can be stored in the same room as the encryptor; however, the CIK must be protected to the same classification level as the encryptor. The CIK may be stored in a separate room from the TACLANE in a secure container that will afford sufficient protection (e.g., a locked cabinet or desk will be sufficient).'
  desc 'check', 'Verify that the VTC Administrator and all other authorized personnel have a copy of the Operational Security Doctrine of the particular encryptor(s) in use at the site, as well as all applicable policies and guidance. 

Verify the following:
• If Type 1 encryptors that use OTAR rekeying methods are operated in a secure facility rated for the highest classification level of the keys used, this is not a finding.
• If Type 1 encryptors that use removable KEYMAT are operated in a secure facility rated for the highest classification level of the keys used and any removable KEYMAT remains with or in the Type 1 encryptor, this is not a finding.
• If Type 1 encryptors that use removable KEYMAT are NOT operated in a secure facility rated for the highest classification level of the keys used, verify the removable KEYMAT is secured in an appropriate secure facility rated for the highest classification level of the KEYMAT or in a GSA-approved container when the system is not in use. If so, this is a finding.'
  desc 'fix', 'Implement Cryptographic Ignition Key handling procedures that comply with Operational Security Doctrine and applicable policies and guidance. Secure each CIK in either a GSA-approved safe or locked cabinet in a secure facility rated for the highest classification level of the KEYMAT.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49188r4_chk'
  tag severity: 'medium'
  tag gid: 'V-43038'
  tag rid: 'SV-55767r1_rule'
  tag stig_id: 'RTS-VTC 7320'
  tag gtitle: 'RTS-VTC 7320 [IP] [ISDN]'
  tag fix_id: 'F-48619r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECCM-1, PESS-1'
end
