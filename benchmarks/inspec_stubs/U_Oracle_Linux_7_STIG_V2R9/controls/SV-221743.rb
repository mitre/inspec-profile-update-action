control 'SV-221743' do
  title 'The Oracle Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are being imported via Network File System (NFS).'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify file systems being NFS imported are configured with the "nosuid" option.

Find the file system(s) that contain the directories being exported with the following command:

# more /etc/fstab | grep nfs

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid 0 0

If a file system found in "/etc/fstab" refers to NFS and it does not have the "nosuid" option set, this is a finding.

Verify the NFS is mounted with the "nosuid" option:

# mount | grep nfs | grep nosuid
If no results are returned, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on file systems that are being imported via NFS.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23458r419301_chk'
  tag severity: 'medium'
  tag gid: 'V-221743'
  tag rid: 'SV-221743r603260_rule'
  tag stig_id: 'OL07-00-021020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23447r419302_fix'
  tag 'documentable'
  tag legacy: ['SV-108329', 'V-99225']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
