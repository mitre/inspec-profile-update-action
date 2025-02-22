control 'SV-805' do
  title 'Removable media, remote file systems, and any file system that does not contain approved setuid files must be mounted with the "nosuid" option.'
  desc 'The "nosuid" mount option causes the system to not execute setuid files with owner privileges.  This option must be used for mounting any file system that does not contain approved setuid files.  Executing setuid files from untrusted file systems, or file systems that do not contain approved setuid files, increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Check /etc/fstab and verify the "nosuid" mount option is used on file systems mounted from removable media, network shares, or any other file system that does not contain approved setuid or setgid files.'
  desc 'fix', 'Edit /etc/fstab and add the "nosuid" mount option to all file systems mounted from removable media or network shares, and any file system that does not contain approved setuid or setgid files.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-529r2_chk'
  tag severity: 'medium'
  tag gid: 'V-805'
  tag rid: 'SV-805r2_rule'
  tag stig_id: 'GEN002420'
  tag gtitle: 'GEN002420'
  tag fix_id: 'F-959r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
