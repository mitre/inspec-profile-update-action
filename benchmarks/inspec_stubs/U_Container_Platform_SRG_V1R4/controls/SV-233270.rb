control 'SV-233270' do
  title 'The container runtime must generate audit records for all container execution, shutdown, restart events, and program initiations.'
  desc 'The container runtime must generate audit records that are specific to the security and mission needs of the organization. Without audit record, it would be difficult to establish, correlate, and investigate events relating to an incident.'
  desc 'check', 'Review the container runtime configuration to validate audit record generation for container execution, shutdown, and restart events. 

If the container runtime does not generate records for container execution, shutdown and restart events, this is a finding.'
  desc 'fix', 'Configure the container runtime to generate audit records for container execution, shutdown, and restart events.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36206r601847_chk'
  tag severity: 'medium'
  tag gid: 'V-233270'
  tag rid: 'SV-233270r879881_rule'
  tag stig_id: 'SRG-APP-000510-CTR-001310'
  tag gtitle: 'SRG-APP-000510'
  tag fix_id: 'F-36174r601298_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
