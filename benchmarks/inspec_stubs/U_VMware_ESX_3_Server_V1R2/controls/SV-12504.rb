control 'SV-12504' do
  title 'A separate file system must be used for user home directories (such as /home or equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /home path is a separate file system.  If it is not, this is a finding.'
  desc 'fix', 'Migrate the /home (or equivalent) path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7967r2_chk'
  tag severity: 'low'
  tag gid: 'V-12003'
  tag rid: 'SV-12504r2_rule'
  tag stig_id: 'GEN003620'
  tag gtitle: 'GEN003620'
  tag fix_id: 'F-11263r2_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
