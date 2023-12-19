control 'SV-222504' do
  title 'The application must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture, audit methods, and provided audit tools.

Identify the application audit tools and their locations.

If the application does not provide a distinct audit tool oriented functionality that is a separate tool with an ability to view and manipulate log data, this requirement is not applicable.

Identify the methods used for implementing an audit tool functionality that is separate from the application. Typical methods are file-oriented in nature, e.g., the application includes a separate executable file or library that when invoked allows users to view and manipulate logs.

Identify the users with the rights to modify the audit tools. This capability will usually be reserved for admin staff.

Review file system permissions to ensure the application audit components such as executable files and libraries are protected by adequate file permission restrictions.

File permissions must be configured to limit access to only those users who have been identified and whose access has been approved.

If file permissions are configured so as to allow unapproved modifications to the audit tools, this is a finding.'
  desc 'fix', 'Configure the application to protect audit tools from unauthorized modifications. Limit users to roles that are assigned the rights to edit or update audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36242r602291_chk'
  tag severity: 'medium'
  tag gid: 'V-222504'
  tag rid: 'SV-222504r879580_rule'
  tag stig_id: 'APSC-DV-001320'
  tag gtitle: 'SRG-APP-000122'
  tag fix_id: 'F-36208r602292_fix'
  tag 'documentable'
  tag legacy: ['SV-84113', 'V-69491']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
