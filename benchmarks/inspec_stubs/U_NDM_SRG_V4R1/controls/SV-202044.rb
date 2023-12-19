control 'SV-202044' do
  title 'The network device must protect audit tools from unauthorized deletion.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operations on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'If the network device provides audit tools, check to see that the network device protects audit tools from unauthorized deletion.  This requirement may be verified by demonstration, configuration review, or validated test results. If the network device does not protect its audit tools from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the network device to protect audit tools from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2170r381740_chk'
  tag severity: 'medium'
  tag gid: 'V-202044'
  tag rid: 'SV-202044r395835_rule'
  tag stig_id: 'SRG-APP-000123-NDM-000240'
  tag gtitle: 'SRG-APP-000123'
  tag fix_id: 'F-2171r381741_fix'
  tag 'documentable'
  tag legacy: ['SV-69451', 'V-55205']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
