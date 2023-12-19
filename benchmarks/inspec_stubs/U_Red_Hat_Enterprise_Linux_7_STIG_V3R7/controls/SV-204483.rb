control 'SV-204483' do
  title 'The Red Hat Enterprise Linux operating system must prevent binary files from being executed on file systems that are being imported via Network File System (NFS).'
  desc 'The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
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
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4607r88641_chk'
  tag severity: 'medium'
  tag gid: 'V-204483'
  tag rid: 'SV-204483r603261_rule'
  tag stig_id: 'RHEL-07-021021'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4607r88642_fix'
  tag 'documentable'
  tag legacy: ['SV-87813', 'V-73161']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
