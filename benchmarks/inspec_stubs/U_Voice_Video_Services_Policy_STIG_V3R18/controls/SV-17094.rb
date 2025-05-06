control 'SV-17094' do
  title 'The Unified Capabilities (UC) soft client Certification and Accreditation (CA) documentation must be included in the CA documentation for the supporting VVoIP system.'
  desc 'Communications applications must be tested and subsequently certified and accredited for IA purposes. This includes the applications and any upgrades or patches. Since a UC soft client is typically supported by a larger VVoIP communications system, the security of the application will affect the security of the overall system. Therefore the C&A documentation for the UC soft client must be included in the C&A documentation for the overall VVoIP system. Subsequently the VVoIP system’s C&A documentation must be included in the C&A documentation for the LAN or enclave.'
  desc 'check', 'Review the site documentation and confirm the UC soft client C&A documentation is included in the C&A documentation for the supporting VVoIP system. If the UC soft client C&A documentation is not included in the C&A documentation for the supporting VVoIP system, this is a finding.'
  desc 'fix', 'Include the UC soft client C&A documentation in the C&A documentation for the supporting VVoIP system and update the Approval To Operate (ATO) with the UC soft client application.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17150r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16106'
  tag rid: 'SV-17094r2_rule'
  tag stig_id: 'VVoIP 1105'
  tag gtitle: 'VVoIP 1105'
  tag fix_id: 'F-16211r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
