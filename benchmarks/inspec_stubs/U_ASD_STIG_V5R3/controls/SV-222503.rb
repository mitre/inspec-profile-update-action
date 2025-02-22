control 'SV-222503' do
  title 'The application must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture, audit methods, and audit tools.

Identify the application audit tools and their locations.

If the application does not provide a distinct audit tool oriented functionality that is a separate tool with an ability to view and manipulate log data, this requirement is not applicable.

Identify the methods used for implementing the audit tool functionality within the application. Typical methods are file system-based, e.g., a separate executable file that when invoked provides audit functionality, an application user interface to an audit module, or a combination thereof.

For file system access: Review file system permissions to ensure the application audit components such as executable files and libraries are protected by adequate file permission restrictions.

Permissions must be configured to limit access to only those who have been identified and whose access has been approved.

If file permissions are configured to allow unapproved access, this is a finding.

For circumstances where audit tools are accessed via application sub-modules or menus: Identify the application module that provides access to audit settings and audit data. Attempt to access audit configuration features and logs by using a regular non-privileged application or database user account.

If a non-privileged user account is allowed to access the audit data or the audit configuration settings, this is a finding.'
  desc 'fix', 'Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36241r602288_chk'
  tag severity: 'medium'
  tag gid: 'V-222503'
  tag rid: 'SV-222503r879579_rule'
  tag stig_id: 'APSC-DV-001310'
  tag gtitle: 'SRG-APP-000121'
  tag fix_id: 'F-36207r602289_fix'
  tag 'documentable'
  tag legacy: ['SV-84111', 'V-69489']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
