control 'SV-202126' do
  title 'The network device must generate audit records when concurrent logons from different workstations occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records when concurrent logons from different workstations occur.

If the network device does not generate audit records when concurrent logons from different workstations occur, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records when concurrent logons from different workstations occur.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2252r382058_chk'
  tag severity: 'medium'
  tag gid: 'V-202126'
  tag rid: 'SV-202126r879877_rule'
  tag stig_id: 'SRG-APP-000506-NDM-000323'
  tag gtitle: 'SRG-APP-000506'
  tag fix_id: 'F-2253r382059_fix'
  tag 'documentable'
  tag legacy: ['SV-69529', 'V-55283']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
