control 'SV-4701' do
  title 'The system must not have the finger service active.'
  desc "The finger service provides information about the system's users to network clients.  This information could expose information that could be used in subsequent attacks."
  desc 'check', 'Determine if the system has the finger service active.  If the finger service is active, this is a finding.'
  desc 'fix', 'Disable the finger service.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2521r2_chk'
  tag severity: 'low'
  tag gid: 'V-4701'
  tag rid: 'SV-4701r2_rule'
  tag stig_id: 'GEN003860'
  tag gtitle: 'GEN003860'
  tag fix_id: 'F-4629r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
