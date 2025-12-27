control 'SV-230939' do
  title 'Forescout must generate log records showing when successful logon attempts occur.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Log records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Verify the syslog trigger is configured.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers.
3. Under User Operations, verify "Include user operations" is checked.

If Forescout does not generate log records when successful logon attempts occur, this is a finding.'
  desc 'fix', 'Configure the syslog trigger.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers.
3. Under User Operations, check "Include user operations".'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33869r603656_chk'
  tag severity: 'low'
  tag gid: 'V-230939'
  tag rid: 'SV-230939r615886_rule'
  tag stig_id: 'FORE-NM-000110'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-33842r603657_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
