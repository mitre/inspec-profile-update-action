control 'SV-230941' do
  title 'Forescout must generate log records showing starting and ending time for administrator access to the system.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Log records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Verify the syslog trigger is configured.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers. 
3. Under User Operations, verify "Include user operations" is checked.

If Forescout does not generate log records showing starting and ending time for administrator access to the system, this is a finding.'
  desc 'fix', 'Configure the syslog trigger.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers. 
3. Under User Operations, check "Include user operations".'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33871r603662_chk'
  tag severity: 'low'
  tag gid: 'V-230941'
  tag rid: 'SV-230941r615886_rule'
  tag stig_id: 'FORE-NM-000130'
  tag gtitle: 'SRG-APP-000505-NDM-000322'
  tag fix_id: 'F-33844r603663_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
