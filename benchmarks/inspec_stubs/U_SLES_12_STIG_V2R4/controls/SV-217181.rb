control 'SV-217181' do
  title 'SUSE operating system file systems that are being imported via Network File System (NFS) must be mounted to prevent binary files from being executed.'
  desc 'The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify the SUSE operating system file systems that are being NFS exported are mounted with the "noexec" option.

Find the file system(s) that contain the directories being exported with the following command:

# more /etc/fstab | grep nfs

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d   /store   nfs   rw,noexec   0 0

If a file system found in "/etc/fstab" refers to NFS and it does not have the "noexec" option set, and use of NFS exported binaries is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system "/etc/fstab" file to use the "noexec" option on file systems that are being exported via NFS.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18409r369699_chk'
  tag severity: 'medium'
  tag gid: 'V-217181'
  tag rid: 'SV-217181r603262_rule'
  tag stig_id: 'SLES-12-010820'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18407r369700_fix'
  tag 'documentable'
  tag legacy: ['SV-91947', 'V-77251']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
