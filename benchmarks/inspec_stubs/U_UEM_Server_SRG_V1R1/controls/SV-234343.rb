control 'SV-234343' do
  title 'The UEM server must protect audit information from unauthorized deletion.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. 

Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. Audit information may include data from other applications or be included with the audit application itself. 

Satisfies:FIA_UAU.1.2, FMT_SMR.1.1(1)'
  desc 'check', 'Verify the UEM server protects audit information from unauthorized deletion.

If the UEM server does not protect audit information from unauthorized deletion, this is a finding'
  desc 'fix', 'Configure the UEM server to protect audit information from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37528r614039_chk'
  tag severity: 'medium'
  tag gid: 'V-234343'
  tag rid: 'SV-234343r617355_rule'
  tag stig_id: 'SRG-APP-000120-UEM-000070'
  tag gtitle: 'SRG-APP-000120'
  tag fix_id: 'F-37493r614040_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
