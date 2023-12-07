control 'SV-230295' do
  title 'A separate RHEL 8 filesystem must be used for the /tmp directory.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system/partition has been created for non-privileged local interactive user home directories.

$ sudo grep /tmp /etc/fstab

/dev/mapper/rhel-tmp  /tmp  xfs   defaults,nodev,nosuid,noexec 0 0 

If a separate entry for the file system/partition "/tmp" does not exist, this is a finding.'
  desc 'fix', 'Migrate the "/tmp" directory onto a separate file system/partition.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32964r567631_chk'
  tag severity: 'medium'
  tag gid: 'V-230295'
  tag rid: 'SV-230295r627750_rule'
  tag stig_id: 'RHEL-08-010543'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-32939r567632_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
