control 'SV-220483' do
  title 'The Cisco switch must be configured to generate audit records when successful/unsuccessful attempts to log on with access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement. The configuration example below will log all logon attempts.

logging logfile LOG_FILE 6
logging level authpri 6

If the Cisco switch is not configured to generate audit records when successful/unsuccessful attempts to logon, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to log all logon attempts as shown in the example below:

Step 1: Lower the authpriv level to 6. 

SW1(config)# logging level authpriv 6

Step 2: Configure a logfile to record log messages at level 6.

SW1(config)# logging logfile LOG_FILE 6'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22198r539170_chk'
  tag severity: 'medium'
  tag gid: 'V-220483'
  tag rid: 'SV-220483r604141_rule'
  tag stig_id: 'CISC-ND-000250'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-22187r539171_fix'
  tag 'documentable'
  tag legacy: ['SV-110615', 'V-101511']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
