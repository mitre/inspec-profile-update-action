control 'SV-233040' do
  title 'The container platform must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the container platform configuration to determine if it is configured to generate audit records when successful/unsuccessful attempts are made to access privileges. 

If the container platform is not configured to generate audit records on successful/unsuccessful access to privileges, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records when successful/unsuccessful attempts are made to access privileges occur.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35976r599524_chk'
  tag severity: 'medium'
  tag gid: 'V-233040'
  tag rid: 'SV-233040r599525_rule'
  tag stig_id: 'SRG-APP-000091-CTR-000160'
  tag gtitle: 'SRG-APP-000091'
  tag fix_id: 'F-35944r598757_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
