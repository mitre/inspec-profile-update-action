control 'SV-218493' do
  title 'The system must use a separate file system for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /var/log/audit path is a separate filesystem.
# grep /var/log/audit /etc/fstab
If no result is returned, /var/log/audit is not on a separate filesystem this is a finding.'
  desc 'fix', 'Migrate the /var/log/audit path onto a separate filesystem.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19968r562615_chk'
  tag severity: 'low'
  tag gid: 'V-218493'
  tag rid: 'SV-218493r603259_rule'
  tag stig_id: 'GEN003623'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19966r562616_fix'
  tag 'documentable'
  tag legacy: ['V-23738', 'SV-64219']
  tag cci: ['CCI-000366', 'CCI-001208']
  tag nist: ['CM-6 b', 'SC-32']
end
