control 'SV-248609' do
  title 'OL 8 must use a separate file system for "/var/log".'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/var/log".

Check that a file system/partition has been created for "/var/log" with the following command:

$ sudo grep /var/log /etc/fstab

UUID=c274f65f /var/log xfs noatime,nobarrier 1 2

If a separate entry for "/var/log" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var/log" path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52043r779391_chk'
  tag severity: 'low'
  tag gid: 'V-248609'
  tag rid: 'SV-248609r779393_rule'
  tag stig_id: 'OL08-00-010541'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51997r779392_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
