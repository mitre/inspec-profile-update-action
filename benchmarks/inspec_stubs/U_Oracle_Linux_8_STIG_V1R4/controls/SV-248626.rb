control 'SV-248626' do
  title 'OL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are imported via Network File System (NFS).'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify that file systems being imported via NFS are mounted with the "nosuid" option with the following command: 
 
$ sudo grep nfs /etc/fstab | grep nosuid 
 
UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid,nodev,noexec 0 0 
 
If a file system found in "/etc/fstab" refers to NFS and it does not have the "nosuid" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on file systems that are being imported via NFS.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52060r779442_chk'
  tag severity: 'medium'
  tag gid: 'V-248626'
  tag rid: 'SV-248626r779444_rule'
  tag stig_id: 'OL08-00-010650'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52014r779443_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
