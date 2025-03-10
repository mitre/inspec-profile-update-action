control 'SV-220510' do
  title 'The Cisco switch must generate audit records showing starting and ending time for administrator access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Verify that the switch is configured to generate log records showing starting and ending time for administrator access as shown in the example below:

logging level authpri 6

If the switch is not configured to generate log records showing starting and ending time for administrator access, this is a finding.'
  desc 'fix', 'Configure the switch to log session start and ending per admin session as shown in the example below:

SW1(config)# logging level authpriv 6'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22225r539251_chk'
  tag severity: 'medium'
  tag gid: 'V-220510'
  tag rid: 'SV-220510r604141_rule'
  tag stig_id: 'CISC-ND-001280'
  tag gtitle: 'SRG-APP-000505-NDM-000322'
  tag fix_id: 'F-22214r539252_fix'
  tag 'documentable'
  tag legacy: ['SV-110669', 'V-101565']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
