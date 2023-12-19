control 'SV-248611' do
  title 'OL 8 must use a separate file system for "/tmp".'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

Check Text: Verify that a separate file system/partition has been created for non-privileged local interactive user home directories.

$ sudo grep /tmp /etc/fstab

/dev/mapper/ol-tmp /tmp xfs defaults,nodev,nosuid,noexec 0 0 

If a separate entry for the file system/partition "/tmp" does not exist, this is a finding.'
  desc 'fix', 'Migrate the "/tmp" directory onto a separate file system/partition.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52045r779397_chk'
  tag severity: 'medium'
  tag gid: 'V-248611'
  tag rid: 'SV-248611r779399_rule'
  tag stig_id: 'OL08-00-010543'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51999r779398_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
