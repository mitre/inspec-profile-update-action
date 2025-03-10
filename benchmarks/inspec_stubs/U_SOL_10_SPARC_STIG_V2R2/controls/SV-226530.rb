control 'SV-226530' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28691r482978_chk'
  tag severity: 'medium'
  tag gid: 'V-226530'
  tag rid: 'SV-226530r603265_rule'
  tag stig_id: 'GEN001480'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-28679r482979_fix'
  tag 'documentable'
  tag legacy: ['V-901', 'SV-901']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
