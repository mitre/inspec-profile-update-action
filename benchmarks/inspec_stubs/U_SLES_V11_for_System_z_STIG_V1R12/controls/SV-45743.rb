control 'SV-45743' do
  title 'The system must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /var path is a separate filesystem.
# grep "/var " /etc/fstab
If no result is returned, /var is not on a separate filesystem this is a finding'
  desc 'fix', 'Migrate the /var path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43103r1_chk'
  tag severity: 'low'
  tag gid: 'V-23736'
  tag rid: 'SV-45743r1_rule'
  tag stig_id: 'GEN003621'
  tag gtitle: 'GEN003621'
  tag fix_id: 'F-39142r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
