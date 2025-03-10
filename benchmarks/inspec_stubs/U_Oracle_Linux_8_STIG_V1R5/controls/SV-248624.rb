control 'SV-248624' do
  title 'OL 8 file systems must not execute binary files that are imported via Network File System (NFS).'
  desc 'The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify that file systems being imported via NFS are mounted with the "noexec" option with the following command: 
 
$ sudo grep nfs /etc/fstab | grep noexec 
 
UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid,nodev,noexec 0 0 
 
If a file system found in "/etc/fstab" refers to NFS and it does not have the "noexec" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "noexec" option on file systems that are being imported via NFS.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52058r779436_chk'
  tag severity: 'medium'
  tag gid: 'V-248624'
  tag rid: 'SV-248624r779438_rule'
  tag stig_id: 'OL08-00-010630'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52012r779437_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
