control 'SV-202041' do
  title 'The network device must protect audit information from unauthorized deletion.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the network device must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order to make access decisions regarding the deletion of audit data.'
  desc 'check', 'Determine if the network device protects audit information from any type of unauthorized deletion with such methods as ensuring log files receive the proper file system permissions utilizing file system protections, restricting access to log data and backing up log data to ensure log data is retained, and leveraging user permissions and roles to identify the user accessing the data and the corresponding rights the user enjoys.   This requirement may be verified by demonstration, configuration, or validated test results. If the network device does not protect audit information from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the network device to protect audit information from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2167r381686_chk'
  tag severity: 'medium'
  tag gid: 'V-202041'
  tag rid: 'SV-202041r879578_rule'
  tag stig_id: 'SRG-APP-000120-NDM-000237'
  tag gtitle: 'SRG-APP-000120'
  tag fix_id: 'F-2168r381687_fix'
  tag 'documentable'
  tag legacy: ['SV-69425', 'V-55179']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
