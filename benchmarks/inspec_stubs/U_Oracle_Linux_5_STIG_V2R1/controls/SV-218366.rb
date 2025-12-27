control 'SV-218366' do
  title 'Removable media, remote file systems, and any file system not containing approved setuid files must be mounted with the nosuid option.'
  desc 'The "nosuid" mount option causes the system to not execute setuid files with owner privileges. This option must be used for mounting any file system not containing approved setuid files. Executing setuid files from untrusted file systems, or file systems not containing approved setuid files, increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Check /etc/mtab and verify the "nosuid" mount option is used on file systems mounted from removable media, network shares, or any other file system not containing approved setuid or setgid files. If any of these files systems do not mount with the "nosuid" option, it is a finding.'
  desc 'fix', 'Edit /etc/fstab and add the "nosuid" mount option to all file systems mounted from removable media or network shares, and any file system not containing approved setuid or setgid files.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19841r569056_chk'
  tag severity: 'medium'
  tag gid: 'V-218366'
  tag rid: 'SV-218366r603259_rule'
  tag stig_id: 'GEN002420'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-19839r569057_fix'
  tag 'documentable'
  tag legacy: ['V-805', 'SV-63441']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
