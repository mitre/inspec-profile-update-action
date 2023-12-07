control 'SV-38747' do
  title 'Removable media, remote file systems, and any file system not containing approved device files must be mounted with the nodev option.'
  desc 'The nodev (or equivalent) mount option causes the system to not handle device files as system devices.  This option must be used for mounting any file system not containing approved device files.  Device files can provide direct access to system hardware and can compromise security if not protected.'
  desc 'check', 'If the system does not support a nodev option, this is not applicable.

Check /etc/filesystems and verify the nodev mount option (options = ) is used on any file systems mounted from removable media or network shares, or file systems not containing any approved device files. If any such file system is not using the nodev option, this is a finding.'
  desc 'fix', 'Edit /etc/filesystems  and add the options = nodev to all entries for remote or removable media file systems, and file systems containing no approved device files.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22368'
  tag rid: 'SV-38747r1_rule'
  tag stig_id: 'GEN002430'
  tag gtitle: 'GEN002430'
  tag fix_id: 'F-32463r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
