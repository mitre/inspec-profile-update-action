control 'SV-216526' do
  title 'The Cisco router must be configured to generate audit records when successful/unsuccessful attempts to logon with access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement. The configuration example below will log all logon attempts.

logging buffered informational
logging 10.1.22.2 vrf default severity info

If the Cisco router is not configured to generate audit records when successful/unsuccessful attempts to logon, this is a finding.'
  desc 'fix', 'Configure the Cisco router to log all logon attempts as shown in the example below.

RP/0/0/CPU0:R3(config)#logging buffered informational 
RP/0/0/CPU0:R3(config)#logging 10.1.22.2 severity info'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17761r288264_chk'
  tag severity: 'medium'
  tag gid: 'V-216526'
  tag rid: 'SV-216526r531088_rule'
  tag stig_id: 'CISC-ND-000250'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-17758r288265_fix'
  tag 'documentable'
  tag legacy: ['SV-105531', 'V-96393']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
