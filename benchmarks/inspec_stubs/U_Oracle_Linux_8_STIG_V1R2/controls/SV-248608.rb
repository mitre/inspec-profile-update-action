control 'SV-248608' do
  title 'OL 8 must use a separate file system for "/var".'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/var" with the following command: 
 
$ sudo grep /var /etc/fstab 
 
UUID=c274f65f /var ext4 noatime,nobarrier 1 2 
 
If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var" path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52042r779388_chk'
  tag severity: 'low'
  tag gid: 'V-248608'
  tag rid: 'SV-248608r779390_rule'
  tag stig_id: 'OL08-00-010540'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51996r779389_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
