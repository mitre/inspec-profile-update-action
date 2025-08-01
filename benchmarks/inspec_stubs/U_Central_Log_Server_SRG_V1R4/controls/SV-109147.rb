control 'SV-109147' do
  title 'The Central Log Server must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server initiates session logging upon startup.

If the Central Log Server is not configured to initiate session logging upon startup, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to initiate session logging upon startup.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98893r1_chk'
  tag severity: 'low'
  tag gid: 'V-100043'
  tag rid: 'SV-109147r1_rule'
  tag stig_id: 'SRG-APP-000092-AU-000670'
  tag gtitle: 'SRG-APP-000092-AU-000670'
  tag fix_id: 'F-105727r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
