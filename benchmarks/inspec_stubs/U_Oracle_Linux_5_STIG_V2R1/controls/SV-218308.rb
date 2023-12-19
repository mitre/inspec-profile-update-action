control 'SV-218308' do
  title 'All user home directories must have mode 0750 or less permissive.'
  desc 'Excessive permissions on home directories allow unauthorized access to user files.'
  desc 'check', "Check the home directory mode of each user in /etc/passwd.

Procedure:
# cut -d: -f6 /etc/passwd|sort|uniq|xargs -n1 ls -ld

If a user home directory's mode is more permissive than 0750, this is a finding.

Note: Application directories are allowed and may need 0755 permissions (or greater) for correct operation."
  desc 'fix', 'Change the mode of user home directories to 0750 or less permissive.

Procedure (example):
# chmod 0750 <home directory>

Note: Application directories are allowed and may need 0755 permissions (or greater) for correct operation.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19783r554261_chk'
  tag severity: 'medium'
  tag gid: 'V-218308'
  tag rid: 'SV-218308r603259_rule'
  tag stig_id: 'GEN001480'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19781r554262_fix'
  tag 'documentable'
  tag legacy: ['V-901', 'SV-64585']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
