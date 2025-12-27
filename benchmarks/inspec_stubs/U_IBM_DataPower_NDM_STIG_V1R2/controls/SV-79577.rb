control 'SV-79577' do
  title 'The DataPower Gateway must limit privileges to change the software resident within software libraries.'
  desc 'Changes to any software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. If the network device were to enable non-authorized users to make changes to software libraries, those changes could be implemented without undergoing testing, validation, and approval.'
  desc 'check', 'Logon page >> Enter non-admin user ID and password, select Default for domain >> Click "Login". If non-admin user can log on, this is a finding.'
  desc 'fix', 'Privileged account user log on to default domain >> Administration >> Access >> User Account >> Select non privileged user account >> Click “…” button next to User Group field >> Enter */default/*?Access=NONE into field >> Click "Add" >> Click "Apply" >> Click "Apply" >> Click "Save Configuration".'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65713r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65087'
  tag rid: 'SV-79577r1_rule'
  tag stig_id: 'WSDP-NM-000045'
  tag gtitle: 'SRG-APP-000133-NDM-000244'
  tag fix_id: 'F-71027r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
