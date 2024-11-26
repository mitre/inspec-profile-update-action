control 'SV-217185' do
  title 'The SUSE operating system must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that the SUSE operating system has a separate file system/partition for "/var".

Check that a file system/partition has been created for "/var" with the following command:

# grep /var /etc/fstab
UUID=c274f65f    /var   ext4   noatime,nobarrier   1 2

If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Create a separate file system/partition on the SUSE operating system for "/var".

Migrate "/var" onto the separate file system/partition.'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18413r369711_chk'
  tag severity: 'low'
  tag gid: 'V-217185'
  tag rid: 'SV-217185r603262_rule'
  tag stig_id: 'SLES-12-010860'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18411r369712_fix'
  tag 'documentable'
  tag legacy: ['V-77265', 'SV-91961']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
