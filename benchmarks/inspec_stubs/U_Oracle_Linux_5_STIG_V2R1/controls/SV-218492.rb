control 'SV-218492' do
  title 'The system must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /var path is a separate filesystem.
# grep /var /etc/fstab
If no result is returned, /var is not on a separate filesystem this is a finding.'
  desc 'fix', 'Migrate the /var path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19967r562612_chk'
  tag severity: 'low'
  tag gid: 'V-218492'
  tag rid: 'SV-218492r603259_rule'
  tag stig_id: 'GEN003621'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19965r562613_fix'
  tag 'documentable'
  tag legacy: ['V-23736', 'SV-64217']
  tag cci: ['CCI-000366', 'CCI-001208']
  tag nist: ['CM-6 b', 'SC-32']
end
