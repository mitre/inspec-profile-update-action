control 'SV-28620' do
  title 'The system must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /var path is a separate file system.  If it is not, this is a finding.'
  desc 'fix', 'Migrate the /var path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28868r1_chk'
  tag severity: 'low'
  tag gid: 'V-23736'
  tag rid: 'SV-28620r1_rule'
  tag stig_id: 'GEN003621'
  tag gtitle: 'GEN003621'
  tag fix_id: 'F-25899r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
