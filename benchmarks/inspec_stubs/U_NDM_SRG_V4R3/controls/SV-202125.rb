control 'SV-202125' do
  title 'The network device must generate audit records showing starting and ending time for administrator access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records showing starting and ending time for administrator access to the system.

If the network device does not generate audit records showing starting and ending time for administrator access to the system, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records showing starting and ending time for administrator access to the system.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2251r382055_chk'
  tag severity: 'medium'
  tag gid: 'V-202125'
  tag rid: 'SV-202125r879876_rule'
  tag stig_id: 'SRG-APP-000505-NDM-000322'
  tag gtitle: 'SRG-APP-000505'
  tag fix_id: 'F-2252r382056_fix'
  tag 'documentable'
  tag legacy: ['SV-69527', 'V-55281']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
