control 'SV-235005' do
  title 'The SUSE operating system must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that the SUSE operating system has a separate file system/partition for "/var".

Check that a file system/partition has been created for "/var" with the following command:

> grep /var /etc/fstab
UUID=c274f65f /var ext4 noatime,nobarrier 1 2

If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Create a separate file system/partition on the SUSE operating system for "/var".

Migrate "/var" onto the separate file system/partition.'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38193r619284_chk'
  tag severity: 'low'
  tag gid: 'V-235005'
  tag rid: 'SV-235005r622137_rule'
  tag stig_id: 'SLES-15-040210'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38156r619285_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
