control 'SV-75335' do
  title 'The Arista Multilayer Switch must generate audit records when concurrent logons from different workstations occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records when concurrent logons from different workstations occur. 

If the network device does not generate audit records when concurrent logons from different workstations occur, this is a finding.

Verify by reviewing log files to show concurrent logons to the system via the "Show Logging" command.'
  desc 'fix', 'Configure the network device to generate audit records when concurrent logons from different workstations occur.

Enable logging level 6 to ensure this event is captured.

Switch(config)#logging trap 6
switch(config)#logging level all 6'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61825r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60877'
  tag rid: 'SV-75335r1_rule'
  tag stig_id: 'AMLS-NM-000380'
  tag gtitle: 'SRG-APP-000506-NDM-000323'
  tag fix_id: 'F-66589r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
