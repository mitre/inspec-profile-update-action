control 'SV-221755' do
  title 'The Oracle Linux operating system must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/var".

Check that a file system/partition has been created for "/var" with the following command:

# grep /var /etc/fstab
UUID=c274f65f /var ext4 noatime,nobarrier 1 2

If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var" path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23470r419337_chk'
  tag severity: 'low'
  tag gid: 'V-221755'
  tag rid: 'SV-221755r603260_rule'
  tag stig_id: 'OL07-00-021320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23459r419338_fix'
  tag 'documentable'
  tag legacy: ['V-99249', 'SV-108353']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
