control 'SV-221744' do
  title 'The Oracle Linux operating system must prevent binary files from being executed on file systems that are being imported via Network File System (NFS).'
  desc 'The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify file systems that are being NFS imported are configured with the "noexec" option.

Find the file system(s) that contain the directories being imported with the following command:

# more /etc/fstab | grep nfs

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,noexec 0 0

If a file system found in "/etc/fstab" refers to NFS and it does not have the "noexec" option set, and use of NFS imported binaries is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the NFS is mounted with the "noexec"option:

# mount | grep nfs | grep noexec
If no results are returned and use of NFS imported binaries is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "noexec" option on file systems that are being imported via NFS.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23459r419304_chk'
  tag severity: 'medium'
  tag gid: 'V-221744'
  tag rid: 'SV-221744r603260_rule'
  tag stig_id: 'OL07-00-021021'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23448r419305_fix'
  tag 'documentable'
  tag legacy: ['V-99227', 'SV-108331']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
