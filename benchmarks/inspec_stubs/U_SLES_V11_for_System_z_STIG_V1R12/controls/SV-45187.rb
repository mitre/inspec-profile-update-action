control 'SV-45187' do
  title 'Removable media, remote file systems, and any file system not containing approved setuid files must be mounted with the nosuid option.'
  desc 'The "nosuid" mount option causes the system to not execute setuid files with owner privileges. This option must be used for mounting any file system not containing approved setuid files. Executing setuid files from untrusted file systems, or file systems not containing approved setuid files, increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Check /etc/fstab and verify the "nosuid" mount option is used on file systems mounted from removable media, network shares, or any other file system not containing approved setuid or setgid files. If any of these files systems do not mount with the "nosuid" option, it is a finding.'
  desc 'fix', 'Edit /etc/fstab and add the "nosuid" mount option to all file systems mounted from removable media or network shares, and any file system not containing approved setuid or setgid files.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42533r1_chk'
  tag severity: 'medium'
  tag gid: 'V-805'
  tag rid: 'SV-45187r1_rule'
  tag stig_id: 'GEN002420'
  tag gtitle: 'GEN002420'
  tag fix_id: 'F-38581r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
