control 'SV-222502' do
  title 'The application must protect audit information from unauthorized deletion.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design.

Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. Audit information may include data from other applications or be included with the audit application itself.'
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture and logging configuration.

Identify the application components and the logs associated with the components.

Identify the roles and users allowed to delete audit information and the circumstances in which they are allowed to delete the data.

Identify the methods used to manage audit records and audit components. Typical methods are file system-based, via an application user interface via database access or a combination thereof.

For file system access: Review file system permissions to ensure the audit logs and the application audit components such as executable files and libraries are protected by adequate file permission restrictions.

Permissions must be configured to limit deletions to only those who have been identified and whose rights to delete audit data and audit configurations has been approved.

If file permissions are configured to allow unapproved deletions of audit settings and data, this is a finding.

For application oriented and database access: Identify the application module that provides access to audit settings and audit data. Attempt to access audit configuration features and logs by using a regular non-privileged application or database user account. Once access has been established, attempt to delete a test audit record and attempt to delete a test audit settings.

If a non-privileged user account is allowed to delete the audit data or the audit configuration settings, this is a finding.'
  desc 'fix', 'Configure the application to protect audit data from unauthorized deletion. Limit users to roles that are assigned the rights to delete audit data and establish permissions that control access to the audit logs and audit configuration settings.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24172r493414_chk'
  tag severity: 'medium'
  tag gid: 'V-222502'
  tag rid: 'SV-222502r508029_rule'
  tag stig_id: 'APSC-DV-001300'
  tag gtitle: 'SRG-APP-000120'
  tag fix_id: 'F-24161r493415_fix'
  tag 'documentable'
  tag legacy: ['SV-84109', 'V-69487']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
