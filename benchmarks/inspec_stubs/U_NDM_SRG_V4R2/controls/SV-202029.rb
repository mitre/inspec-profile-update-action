control 'SV-202029' do
  title 'The network device must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Determine if the network device initiates session auditing upon startup. This requirement may be verified by validated test results. If the network device does not initiate session auditing upon startup, this is a finding.'
  desc 'fix', 'Configure the network device to initiate session auditing upon startup.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2155r381653_chk'
  tag severity: 'medium'
  tag gid: 'V-202029'
  tag rid: 'SV-202029r879562_rule'
  tag stig_id: 'SRG-APP-000092-NDM-000224'
  tag gtitle: 'SRG-APP-000092'
  tag fix_id: 'F-2156r381654_fix'
  tag 'documentable'
  tag legacy: ['SV-69339', 'V-55093']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
