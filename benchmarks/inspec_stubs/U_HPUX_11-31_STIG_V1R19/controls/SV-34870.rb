control 'SV-34870' do
  title 'All user home directories must have mode 0750 or less permissive.'
  desc 'Excessive permissions on home directories allow unauthorized access to user files.'
  desc 'check', %q(Check the home directory mode of each user in /etc/passwd.

Procedure:
# ls -lLd `cat /etc/passwd | cut -f 6,6 -d ":"` | more

If a user's home directory mode is more permissive than 0750, this is a finding.

NOTE: Application directories are allowed to and may need 0755 permissions (or greater) for correct operation.)
  desc 'fix', "Change the mode of user's home directory to 0750 or less permissive.

Procedure (example):
# chmod 0750 <home directory>

NOTE: Application directories are allowed to and may need 0755 permissions (or greater) for correct operation."
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36335r1_chk'
  tag severity: 'medium'
  tag gid: 'V-901'
  tag rid: 'SV-34870r1_rule'
  tag stig_id: 'GEN001480'
  tag gtitle: 'GEN001480'
  tag fix_id: 'F-31590r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
