control 'SV-901' do
  title "All users' home directories must have mode 0750 or less permissive."
  desc "Excessive permissions on home directories allow unauthorized access to user's files."
  desc 'check', "Check the home directory mode of each user in /etc/passwd.

Procedure:
# cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld | more

If a user's home directory's mode is more permissive than 0750, this is a finding.

NOTE: Application directories are allowed and may need 0755 permissions (or greater) for correct operation."
  desc 'fix', "Change the mode of users' home directories to 0750 or less permissive.

Procedure (example):
# chmod 0750 <home directory>"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-8017r3_chk'
  tag severity: 'medium'
  tag gid: 'V-901'
  tag rid: 'SV-901r2_rule'
  tag stig_id: 'GEN001480'
  tag gtitle: 'GEN001480'
  tag fix_id: 'F-1055r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
