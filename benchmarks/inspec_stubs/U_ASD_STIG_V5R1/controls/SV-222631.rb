control 'SV-222631' do
  title 'Access privileges to the Configuration Management (CM) repository must be reviewed every three months.'
  desc 'A Configuration Management (CM) repository is used to manage application code versions and to securely store application code.

Incorrect access privileges to the CM repository can lead to malicious code or unintentional code being introduced into the application.

This requirement is intended to be applied to application developers or organizations responsible for code management or who have and operate an application CM repository.'
  desc 'check', 'Review the application system documentation.

Interview the application administrator.

Identify if development of the application is done in house and if application configuration management repository exists.

If application development is not done in house and if a code configuration management repository does not exist, the requirement is not applicable.

Review CM management processes and procedures.

Verify the CM repository access permissions are reviewed at least every three months.

Ask the application administrator or the CM administrator when the last time the CM access privileges were reviewed.

If CM access privileges have not been reviewed within the last three months, this is a finding.'
  desc 'fix', 'Review access privileges to the CM repository at least every three months.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24301r493801_chk'
  tag severity: 'medium'
  tag gid: 'V-222631'
  tag rid: 'SV-222631r508029_rule'
  tag stig_id: 'APSC-DV-003000'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24290r493802_fix'
  tag 'documentable'
  tag legacy: ['SV-84963', 'V-70341']
  tag cci: ['CCI-000366', 'CCI-001795']
  tag nist: ['CM-6 b', 'CM-9 b']
end
