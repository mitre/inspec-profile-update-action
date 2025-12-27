control 'SV-45190' do
  title 'Removable media, remote file systems, and any file system not containing approved device files must be mounted with the nodev option.'
  desc 'The "nodev" (or equivalent) mount option causes the system to not handle device files as system devices. This option must be used for mounting any file system not containing approved device files. Device files can provide direct access to system hardware and can compromise security if not protected.'
  desc 'check', 'Check /etc/fstab and verify the "nodev" mount option is used on any filesystems mounted from removable media or network shares. If any filesystem mounted from removable media or network shares does not have this option, this is a finding.'
  desc 'fix', 'Edit /etc/fstab and add the "nodev" option to any filesystems mounted from removable media or network shares.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42537r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22368'
  tag rid: 'SV-45190r1_rule'
  tag stig_id: 'GEN002430'
  tag gtitle: 'GEN002430'
  tag fix_id: 'F-38585r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
