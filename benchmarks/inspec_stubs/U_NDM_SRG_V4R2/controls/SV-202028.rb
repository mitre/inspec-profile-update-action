control 'SV-202028' do
  title 'The network device must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records when successful/unsuccessful attempts to access privileges occur. If the network device does not generate audit records when successful/unsuccessful attempts to access privileges occur, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records when successful/unsuccessful attempts to access privileges occur.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2154r381650_chk'
  tag severity: 'medium'
  tag gid: 'V-202028'
  tag rid: 'SV-202028r879561_rule'
  tag stig_id: 'SRG-APP-000091-NDM-000223'
  tag gtitle: 'SRG-APP-000091'
  tag fix_id: 'F-2155r381651_fix'
  tag 'documentable'
  tag legacy: ['SV-69337', 'V-55091']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
