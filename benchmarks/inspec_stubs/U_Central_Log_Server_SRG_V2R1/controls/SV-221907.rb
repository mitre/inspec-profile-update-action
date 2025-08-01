control 'SV-221907' do
  title 'The Central Log Server must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server initiates session logging upon startup.

If the Central Log Server is not configured to initiate session logging upon startup, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to initiate session logging upon startup.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23622r420063_chk'
  tag severity: 'low'
  tag gid: 'V-221907'
  tag rid: 'SV-221907r420065_rule'
  tag stig_id: 'SRG-APP-000092-AU-000670'
  tag gtitle: 'SRG-APP-000092'
  tag fix_id: 'F-23611r420064_fix'
  tag 'documentable'
  tag legacy: ['SV-109147', 'V-100043']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
