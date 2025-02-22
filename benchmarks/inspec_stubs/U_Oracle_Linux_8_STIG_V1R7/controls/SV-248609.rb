control 'SV-248609' do
  title 'OL 8 must use a separate file system for "/var/log".'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system has been created for "/var/log".

Check that a file system has been created for "/var/log" with the following command:

     $ sudo grep /var/log /etc/fstab

     /dev/mapper/...   /var/log   xfs   defaults,nodev,noexec,nosuid 0 0

If a separate entry for "/var/log" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var/log" path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52043r902794_chk'
  tag severity: 'low'
  tag gid: 'V-248609'
  tag rid: 'SV-248609r902795_rule'
  tag stig_id: 'OL08-00-010541'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51997r779392_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
