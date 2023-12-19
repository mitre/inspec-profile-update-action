control 'SV-222500' do
  title 'The application must protect audit information from any type of unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult if not impossible to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, and copy access.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture and logging configuration.

Identify the application components and the logs associated with the components.

Identify the roles and users allowed to access audit information and the circumstances in which they are allowed to read or otherwise access the data.

Identify the methods used to manage audit records and audit components. Typical methods are file system-based, via an application user interface via database access or a combination thereof.

For file system access: Review file system permissions to ensure the audit logs and the application audit components such as executable files and libraries are protected by adequate file permission restrictions.

Permissions must be configured to limit access to only those who have been identified and whose access has been approved.

If file permissions are configured to allow unapproved access, this is a finding.

For application-oriented and database access: Identify the application module that provides access to audit settings and audit data. Attempt to access audit configuration features and logs by using a regular non-privileged application or database user account.

If a non-privileged user account is allowed to access the audit data or the audit configuration settings, this is a finding.'
  desc 'fix', 'Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish permissions that control access to the audit logs and audit configuration settings.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24170r493408_chk'
  tag severity: 'medium'
  tag gid: 'V-222500'
  tag rid: 'SV-222500r508029_rule'
  tag stig_id: 'APSC-DV-001280'
  tag gtitle: 'SRG-APP-000118'
  tag fix_id: 'F-24159r493409_fix'
  tag 'documentable'
  tag legacy: ['V-69483', 'SV-84105']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
