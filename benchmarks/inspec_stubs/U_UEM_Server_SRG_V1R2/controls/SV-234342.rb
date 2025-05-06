control 'SV-234342' do
  title 'The UEM server must protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Satisfies:FIA_UAU.1.2, FMT_SMR.1.1(1)'
  desc 'check', 'Verify the UEM server protects audit information from unauthorized modification.

If the UEM server does not protect audit information from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the UEM server to protect audit information from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37527r614036_chk'
  tag severity: 'medium'
  tag gid: 'V-234342'
  tag rid: 'SV-234342r879577_rule'
  tag stig_id: 'SRG-APP-000119-UEM-000069'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-37492r614037_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
