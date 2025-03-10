control 'SV-202043' do
  title 'The network device must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'If the network device provides audit tools, check the device to determine if it protects audit tools from unauthorized modification. This requirement may be verified by demonstration, configuration review, or validated test results. If the network device does not protect its audit tools from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the network device to protect audit tools from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2169r381737_chk'
  tag severity: 'medium'
  tag gid: 'V-202043'
  tag rid: 'SV-202043r395832_rule'
  tag stig_id: 'SRG-APP-000122-NDM-000239'
  tag gtitle: 'SRG-APP-000122'
  tag fix_id: 'F-2170r381738_fix'
  tag 'documentable'
  tag legacy: ['SV-69437', 'V-55191']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
