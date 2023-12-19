control 'SV-217180' do
  title 'SUSE operating system file systems that are being imported via Network File System (NFS) must be mounted to prevent files with the setuid and setgid bit set from being executed.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify SUSE operating system file systems that are being NFS exported are mounted with the "nosuid" option.

Find the file system(s) that contain the directories being exported with the following command:

# more /etc/fstab | grep nfs

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d   /store   nfs   rw,nosuid   0 0

If a file system found in "/etc/fstab" refers to NFS and it does not have the "nosuid" option set, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system "/etc/fstab" file to use the "nosuid" option on file systems that are being exported via NFS.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18408r369696_chk'
  tag severity: 'medium'
  tag gid: 'V-217180'
  tag rid: 'SV-217180r603262_rule'
  tag stig_id: 'SLES-12-010810'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18406r369697_fix'
  tag 'documentable'
  tag legacy: ['SV-91937', 'V-77241']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
