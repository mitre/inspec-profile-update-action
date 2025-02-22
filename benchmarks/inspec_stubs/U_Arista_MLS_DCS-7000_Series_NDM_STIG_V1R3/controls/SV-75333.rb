control 'SV-75333' do
  title 'The Arista Multilayer Switch must generate audit records showing starting and ending time for administrator access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records showing starting and ending time for administrator access to the system. 

If the network device does not generate audit records showing starting and ending time for administrator access to the system, this is a finding.

Verify by reviewing log files to show start and end times for administrator access to the system via the "show logging" command.'
  desc 'fix', 'Configure the network device to generate audit records showing starting and ending time for administrator access to the system.

Enable logging level 6 to ensure this event is captured.

Switch(config)#logging trap 6
switch(config)#logging level all 6'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61823r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60875'
  tag rid: 'SV-75333r1_rule'
  tag stig_id: 'AMLS-NM-000370'
  tag gtitle: 'SRG-APP-000505-NDM-000322'
  tag fix_id: 'F-66587r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
