control 'SV-202042' do
  title 'The network device must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'If the network device provides audit tools, check the device to determine if it protects audit tools from unauthorized access.  This requirement may be verified by demonstration, configuration review, or validated test results. If the network device does not protect its audit tools from unauthorized access, this is a finding.'
  desc 'fix', 'Configure the network device to protect audit tools from unauthorized access.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2168r381689_chk'
  tag severity: 'medium'
  tag gid: 'V-202042'
  tag rid: 'SV-202042r395829_rule'
  tag stig_id: 'SRG-APP-000121-NDM-000238'
  tag gtitle: 'SRG-APP-000121'
  tag fix_id: 'F-2169r381690_fix'
  tag 'documentable'
  tag legacy: ['SV-69429', 'V-55183']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
