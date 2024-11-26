control 'SV-38746' do
  title 'Removable media, remote file systems, and any file system not containing approved setuid files must be mounted with the nosuid option.'
  desc 'The nosuid mount option causes the system to not execute setuid files with owner privileges.  This option must be used for mounting any file system not containing approved setuid files.  Executing setuid files from untrusted file systems, or file systems not containing approved setuid files, increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Check /etc/filesystems and verify the nosuid mount option is used on file systems mounted from removable media, network shares, or any other file system not containing  approved setuid or setgid files.

Each file system stanza  must contain a device special file and may additionally contain all of the following fields
type = , options = ,  and  check = .

# more /etc/filesystems
# lsfs

If any of these files systems do not mount with the nosuid option, it is a finding.'
  desc 'fix', 'Edit /etc/filesystems and add the options = nosuid to the stanza of file system mounted from removable media or network shares, and any file system not containing approved setuid or setgid files.

OR

Add the nosuid option with the chfs command.
# chfs -a options=nosuid  <filesystem>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37185r1_chk'
  tag severity: 'medium'
  tag gid: 'V-805'
  tag rid: 'SV-38746r1_rule'
  tag stig_id: 'GEN002420'
  tag gtitle: 'GEN002420'
  tag fix_id: 'F-32462r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
