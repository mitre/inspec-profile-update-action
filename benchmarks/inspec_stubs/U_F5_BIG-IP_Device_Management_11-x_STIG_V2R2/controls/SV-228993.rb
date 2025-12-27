control 'SV-228993' do
  title 'The application must be configured to reveal error messages only to authorized individuals (ISSO, ISSM, and SA).'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state. Additionally, sensitive account information must not be revealed through error messages to unauthorized personnel or their designated representatives."
  desc 'check', 'Verify the BIG-IP appliance is configured to reveal error messages only to authorized individuals (ISSO, ISSM, and SA). 

Navigate to the BIG-IP System manager >> Logs >> Configuration >> Options.

Verify that "Log Access" is granted only to authorized individuals (ISSO, ISSM, and SA).

If the BIG-IP appliance reveals error messages to any unauthorized individuals (ISSO, ISSM, and SA), this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to reveal error messages only to authorized individuals (ISSO, ISSM, and SA).'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31308r518024_chk'
  tag severity: 'medium'
  tag gid: 'V-228993'
  tag rid: 'SV-228993r879887_rule'
  tag stig_id: 'F5BI-DM-000151'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31285r518025_fix'
  tag 'documentable'
  tag legacy: ['V-60173', 'SV-74603']
  tag cci: ['CCI-000366', 'CCI-001314']
  tag nist: ['CM-6 b', 'SI-11 b']
end
