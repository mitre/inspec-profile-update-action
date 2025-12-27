control 'SV-234326' do
  title 'The UEM server must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter). 

Satisfies:FAU_GEN.1.1(1)'
  desc 'check', 'Verify the UEM server generates audit records when successful/unsuccessful attempts to access privileges occur.

If the UEM server does not generate audit records when successful/unsuccessful attempts to access privileges occur, this is a finding.'
  desc 'fix', 'Configure the UEM server to generate audit records when successful/unsuccessful attempts to access privileges occur.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37511r613988_chk'
  tag severity: 'medium'
  tag gid: 'V-234326'
  tag rid: 'SV-234326r617355_rule'
  tag stig_id: 'SRG-APP-000091-UEM-000052'
  tag gtitle: 'SRG-APP-000091'
  tag fix_id: 'F-37476r613989_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
