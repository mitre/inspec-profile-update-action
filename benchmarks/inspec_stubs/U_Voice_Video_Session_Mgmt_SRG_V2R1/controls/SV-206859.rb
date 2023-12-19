control 'SV-206859' do
  title 'The Voice Video Session Manager must be configured to obfuscate passwords within configuration files.'
  desc 'Passwords need to be protected at all times and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Voice Video Session Managers must enforce password encryption when storing passwords within configuration files.'
  desc 'check', 'Verify the Voice Video Session Manager is configured to obfuscate passwords within configuration files.

If the Voice Video Session Manager is not configured to obfuscate passwords within configuration files, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to obfuscate passwords within configuration files.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7114r364766_chk'
  tag severity: 'medium'
  tag gid: 'V-206859'
  tag rid: 'SV-206859r508661_rule'
  tag stig_id: 'SRG-NET-000512-VVSM-00054'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7114r364767_fix'
  tag 'documentable'
  tag legacy: ['V-71683', 'SV-86307']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
