control 'SV-222505' do
  title 'The application must protect audit tools from unauthorized deletion.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture, audit methods and provided audit tools.

Identify the application audit tools and their locations.

If the application does not provide a distinct audit tool oriented functionality that is a separate tool with an ability to view and manipulate log data, this requirement is not applicable.

Identify the methods used for implementing an audit tool functionality that is separate from the application. Typical methods are file-oriented in nature, e.g., the application includes a separate executable file or library that when invoked allows users to view and manipulate logs.

Identify the users with the rights to delete the audit tools. This capability is normally reserved for admin staff.

Review file system permissions to ensure the application audit components such as executable files and libraries are protected by adequate file permission restrictions.

File permissions must be configured to limit access to only those users who have been identified and whose access has been approved.

If file permissions are configured to allow unapproved deletions of the audit tools, this is a finding.'
  desc 'fix', 'Configure the application to protect audit tools from unauthorized deletions. Limit users to roles that are assigned the rights to edit or delete audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24175r561243_chk'
  tag severity: 'medium'
  tag gid: 'V-222505'
  tag rid: 'SV-222505r561245_rule'
  tag stig_id: 'APSC-DV-001330'
  tag gtitle: 'SRG-APP-000123'
  tag fix_id: 'F-24164r561244_fix'
  tag 'documentable'
  tag legacy: ['SV-84115', 'V-69493']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
