control 'SV-234980' do
  title 'The SUSE operating system must use a separate file system for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that the SUSE operating system has a separate file system/partition for the system audit data path.

Check that a file system/partition has been created for the system audit data path with the following command:

Note: "/var/log/audit" is used as the example as it is a common location.

> grep /var/log/audit /etc/fstab
UUID=3645951a /var/log/audit ext4 defaults 1 2

If a separate entry for the system audit data path (in this example the "/var/log/audit" path) does not exist, ask the System Administrator if the system audit logs are being written to a different file system/partition on the system and then grep for that file system/partition. 

If a separate file system/partition does not exist for the system audit data path, this is a finding.'
  desc 'fix', 'Migrate the SUSE operating system audit data path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38168r619209_chk'
  tag severity: 'low'
  tag gid: 'V-234980'
  tag rid: 'SV-234980r622137_rule'
  tag stig_id: 'SLES-15-030810'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38131r619210_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
