control 'SV-45745' do
  title 'The system must use a separate file system for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /var/log/audit path is a separate filesystem.
# grep "/var/log/audit " /etc/fstab
If no result is returned, /var/log/audit is not on a separate filesystem this is a finding.'
  desc 'fix', 'Migrate the /var/log/audit path onto a separate filesystem.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43104r1_chk'
  tag severity: 'low'
  tag gid: 'V-23738'
  tag rid: 'SV-45745r1_rule'
  tag stig_id: 'GEN003623'
  tag gtitle: 'GEN003623'
  tag fix_id: 'F-39145r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
