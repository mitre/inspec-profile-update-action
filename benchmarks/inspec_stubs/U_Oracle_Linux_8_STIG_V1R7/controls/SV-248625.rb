control 'SV-248625' do
  title 'OL 8 file systems must not interpret character or block special devices that are imported via NFS.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify that file systems being imported via NFS are mounted with the "nodev" option with the following command: 
 
$ sudo grep nfs /etc/fstab | grep nodev 
 
UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid,nodev,noexec 0 0 
 
If a file system found in "/etc/fstab" refers to NFS and it does not have the "nodev" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nodev" option on file systems that are being imported via NFS.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52059r779439_chk'
  tag severity: 'medium'
  tag gid: 'V-248625'
  tag rid: 'SV-248625r779441_rule'
  tag stig_id: 'OL08-00-010640'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52013r779440_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
