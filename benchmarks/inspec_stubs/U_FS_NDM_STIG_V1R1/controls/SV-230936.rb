control 'SV-230936' do
  title 'Forescout must generate log records when successful attempts to access privileges occur.'
  desc 'Without generating log records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Log records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the syslog trigger is configured.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers.
3. Under "User Operations", verify "Include user operations" is checked.

If Forescout does not generate log records when successful attempts to access privileges occur, this is a finding.'
  desc 'fix', 'Configure the syslog trigger.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers.
3. Under "User Operations", check "Include user operations".'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33866r603647_chk'
  tag severity: 'low'
  tag gid: 'V-230936'
  tag rid: 'SV-230936r615886_rule'
  tag stig_id: 'FORE-NM-000080'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-33839r603648_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
