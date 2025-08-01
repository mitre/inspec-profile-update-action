control 'SV-202040' do
  title 'The network device must protect audit information from unauthorized modification.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit network device activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the network device must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.'
  desc 'check', 'Determine if the network device protects audit information from any type of unauthorized modification with such methods as ensuring log files receive the proper file system permissions, limiting log data locations and leveraging user permissions and roles to identify the user accessing the data and the corresponding rights that the user enjoys. This requirement may be verified by demonstration, configuration, or validated test results. If the network device does not protect audit information from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the network device to protect audit information from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2166r381683_chk'
  tag severity: 'medium'
  tag gid: 'V-202040'
  tag rid: 'SV-202040r395823_rule'
  tag stig_id: 'SRG-APP-000119-NDM-000236'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-2167r381684_fix'
  tag 'documentable'
  tag legacy: ['SV-69419', 'V-55173']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
