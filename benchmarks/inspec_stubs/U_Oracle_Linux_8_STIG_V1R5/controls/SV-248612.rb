control 'SV-248612' do
  title 'OL 8 must use a separate file system for /var/tmp.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/var/tmp".

Check that a file system/partition has been created for "/var/tmp" with the following command:

$ sudo grep /var/tmp /etc/fstab

UUID=c274f65f /var/tmp xfs noatime,nobarrier 1 2

If a separate entry for "/var/tmp" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var/tmp" path onto a separate file system.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52046r779400_chk'
  tag severity: 'medium'
  tag gid: 'V-248612'
  tag rid: 'SV-248612r779402_rule'
  tag stig_id: 'OL08-00-010544'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52000r779401_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
