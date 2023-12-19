control 'SV-230942' do
  title 'Forescout must generate log records when concurrent logons from different workstations occur.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Log records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Verify the syslog trigger is configured.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers. 
3. Under User Operations, verify "Include user operations" is checked.

If Forescout does not generate log records when concurrent logons from different workstations occur, this is a finding.'
  desc 'fix', 'Configure the syslog trigger.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers.
3. Under User Operations, check "Include user operations".'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33872r603665_chk'
  tag severity: 'low'
  tag gid: 'V-230942'
  tag rid: 'SV-230942r615886_rule'
  tag stig_id: 'FORE-NM-000140'
  tag gtitle: 'SRG-APP-000506-NDM-000323'
  tag fix_id: 'F-33845r603666_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
