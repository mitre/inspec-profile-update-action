control 'SV-230292' do
  title 'RHEL 8 must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/var".

Check that a file system/partition has been created for "/var" with the following command:

$ sudo grep /var /etc/fstab

UUID=c274f65f /var xfs noatime,nobarrier 1 2

If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var" path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32961r567622_chk'
  tag severity: 'low'
  tag gid: 'V-230292'
  tag rid: 'SV-230292r627750_rule'
  tag stig_id: 'RHEL-08-010540'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-32936r567623_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
