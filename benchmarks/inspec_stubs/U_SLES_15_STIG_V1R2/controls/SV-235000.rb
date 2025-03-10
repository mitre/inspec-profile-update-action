control 'SV-235000' do
  title 'SUSE operating system file systems that are being imported via Network File System (NFS) must be mounted to prevent files with the setuid and setgid bit set from being executed.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify SUSE operating system file systems that are being NFS exported are mounted with the "nosuid" option.

Find the file system(s) that contain the directories being exported with the following command:

> grep nfs /etc/fstab

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid 0 0

If a file system found in "/etc/fstab" refers to NFS and it does not have the "nosuid" option set, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system "/etc/fstab" file to use the "nosuid" option on file systems that are being exported via NFS.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38188r619269_chk'
  tag severity: 'medium'
  tag gid: 'V-235000'
  tag rid: 'SV-235000r622137_rule'
  tag stig_id: 'SLES-15-040160'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38151r619270_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
