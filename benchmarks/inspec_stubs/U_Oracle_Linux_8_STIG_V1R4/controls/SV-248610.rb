control 'SV-248610' do
  title 'OL 8 must use a separate file system for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system/partition has been created for the system audit data path with the following command: 
 
Note: "/var/log/audit" is used as the example as it is a common location. 
 
$ sudo grep /var/log/audit /etc/fstab 
 
UUID=3645951a /var/log/audit ext4 defaults 1 2 
 
If an entry for "/var/log/audit" does not exist, ask the System Administrator if the system audit logs are being written to a different file system/partition on the system and then grep for that file system/partition. 
 
If a separate file system/partition does not exist for the system audit data path, this is a finding.'
  desc 'fix', 'Migrate the system audit data path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52044r779394_chk'
  tag severity: 'low'
  tag gid: 'V-248610'
  tag rid: 'SV-248610r779396_rule'
  tag stig_id: 'OL08-00-010542'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51998r779395_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
