control 'SV-234683' do
  title 'Oracle JRE 8 must have a deployment.config file present.'
  desc '<0> [object Object]'
  desc 'check', 'By default, no "deployment.config" file exists; it must be created. Verify a "deployment.config" configuration file exists in either:

<Windows Directory>\\Sun\\Java\\Deployment\\deployment.config
- or -
<JRE Installation Directory>\\Lib\\deployment.config

If the "deployment.config" configuration file does not exist in either of these folders, this is a finding.'
  desc 'fix', 'By default, no "deployment.config" file exists; a text file must be created. Create a JRE deployment configuration file in either:

<Windows Directory>\\Sun\\Java\\Deployment\\deployment.config
- or -
<JRE Installation Directory>\\Lib\\deployment.config'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37868r616105_chk'
  tag severity: 'medium'
  tag gid: 'V-234683'
  tag rid: 'SV-234683r617446_rule'
  tag stig_id: 'JRE8-WN-000010'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37833r616106_fix'
  tag legacy: ['V-66939', 'SV-81429']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
