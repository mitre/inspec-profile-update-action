control 'SV-28627' do
  title 'The system must use a separate file system for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the system audit data path is a separate file system.  If it is not, this is a finding.'
  desc 'fix', 'Migrate the system audit data path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28876r1_chk'
  tag severity: 'low'
  tag gid: 'V-23738'
  tag rid: 'SV-28627r1_rule'
  tag stig_id: 'GEN003623'
  tag gtitle: 'GEN003623'
  tag fix_id: 'F-25904r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
