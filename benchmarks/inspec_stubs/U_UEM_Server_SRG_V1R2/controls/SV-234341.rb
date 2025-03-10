control 'SV-234341' do
  title 'The UEM server must protect audit information from any type of unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult if not impossible to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, and copy access.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, applications with user interfaces to audit records must not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Satisfies:FIA_UAU.1.2, FMT_SMR.1.1(1)'
  desc 'check', 'Verify the UEM server protects audit information from any type of unauthorized read access.

If the UEM server does not protect audit information from any type of unauthorized read access, this is a finding'
  desc 'fix', 'Configure the UEM server to protect audit information from any type of unauthorized read access.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37526r614033_chk'
  tag severity: 'medium'
  tag gid: 'V-234341'
  tag rid: 'SV-234341r879576_rule'
  tag stig_id: 'SRG-APP-000118-UEM-000068'
  tag gtitle: 'SRG-APP-000118'
  tag fix_id: 'F-37491r614034_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
