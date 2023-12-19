control 'SV-222501' do
  title 'The application must protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture and logging configuration.

Identify the application components and the logs associated with the components.

Identify the roles and users allowed to modify audit information and the circumstances in which they are allowed to modify the data.

Identify the methods used to manage audit records and audit components. Typical methods are file system-based, via an application user interface via database access or a combination thereof.

For file system access: Review file system permissions to ensure the audit logs and the application audit components such as executable files and libraries are protected by adequate file permission restrictions.

Permissions must be configured to limit write/modify access to only those who have been identified and whose access has been approved.

If file permissions are configured to allow unapproved write/modify access, this is a finding.

For application oriented and database access: Identify the application module that provides access to audit settings and audit data. Attempt to access audit configuration features and logs by using a regular non-privileged application or database user account. Once access has been established, attempt to modify an audit record and attempt to modify the audit settings.

If a non-privileged user account is allowed to modify the audit data or the audit configuration settings, this is a finding.'
  desc 'fix', 'Configure the application to protect audit data from unauthorized modification and changes. Limit users to roles that are assigned the rights to edit audit data and establish permissions that control access to the audit logs and audit configuration settings.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24171r561237_chk'
  tag severity: 'medium'
  tag gid: 'V-222501'
  tag rid: 'SV-222501r561239_rule'
  tag stig_id: 'APSC-DV-001290'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-24160r561238_fix'
  tag 'documentable'
  tag legacy: ['SV-84107', 'V-69485']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
