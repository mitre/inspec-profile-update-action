control 'SV-230938' do
  title 'Forescout must generate log records when attempts to delete administrator privileges occur.'
  desc 'Without generating log records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Log records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Verify the syslog trigger is configured.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers.
3. Under User Operations, verify "Include user operations" is checked.

If Forescout does not generate log records when attempts to delete administrator privileges occur, this is a finding.'
  desc 'fix', 'Configure the syslog trigger.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers.
3. Under User Operations, check "Include user operations".'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33868r603653_chk'
  tag severity: 'low'
  tag gid: 'V-230938'
  tag rid: 'SV-230938r615886_rule'
  tag stig_id: 'FORE-NM-000100'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-33841r603654_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
