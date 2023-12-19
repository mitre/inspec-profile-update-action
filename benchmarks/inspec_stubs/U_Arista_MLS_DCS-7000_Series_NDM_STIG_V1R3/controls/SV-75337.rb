control 'SV-75337' do
  title 'The Arista Multilayer Switch must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records for all account creations, modifications, disabling, and termination events. 

If the network device does not generate audit records for all account creations, modifications, disabling, and termination events, this is a finding.

Verify by reviewing log files to show audit records for account creation, modification, disabling, and termination via the "Show Logging" command.'
  desc 'fix', 'Configure the network device to generate audit records for all account creations, modifications, disabling, and termination events.

Enable logging level 6 to ensure this event is captured:

Switch(config)#logging trap 6
switch(config)#logging level all 6'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61827r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60879'
  tag rid: 'SV-75337r1_rule'
  tag stig_id: 'AMLS-NM-000390'
  tag gtitle: 'SRG-APP-000509-NDM-000324'
  tag fix_id: 'F-66591r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
