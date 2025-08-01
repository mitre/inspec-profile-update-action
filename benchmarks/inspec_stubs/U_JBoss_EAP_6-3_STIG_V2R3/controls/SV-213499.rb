control 'SV-213499' do
  title 'Users in JBoss Management Security Realms must be in the appropriate role.'
  desc 'Security realms are a series of mappings between users and passwords and users and roles.  There are 2 JBoss security realms provided by default; they are "management realm" and "application realm".

Management realm stores authentication information for the management API, which provides functionality for the web-based management console and the management command line interface (CLI).

mgmt-groups.properties stores user to group mapping for the ManagementRealm but only when role-based access controls  (RBAC) is enabled.

If management users are not in the appropriate role, unauthorized access to JBoss resources can occur.'
  desc 'check', 'Review the mgmt-users.properties file.   Also review the <management /> section in the standalone.xml or domain.xml configuration files.  The relevant xml file will depend on if the JBoss server is configured in standalone or domain mode.

Ensure all users listed in these files are approved for management access to the JBoss server and are in the appropriate role.

For domain configurations:
<JBOSS_HOME>/domain/configuration/mgmt-users.properties.  
<JBOSS_HOME>/domain/configuration/domain.xml

For standalone configurations:
<JBOSS_HOME>/standalone/configuration/mgmt-users.properties.
<JBOSS_HOME>/standalone/configuration/standalone.xml

If the users listed are not in the appropriate role, this is a finding.'
  desc 'fix', 'Document approved management users and their roles.  Configure the application server to use RBAC and ensure users are placed into the appropriate roles.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14722r296163_chk'
  tag severity: 'medium'
  tag gid: 'V-213499'
  tag rid: 'SV-213499r615939_rule'
  tag stig_id: 'JBOS-AS-000040'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-14720r296164_fix'
  tag 'documentable'
  tag legacy: ['SV-76709', 'V-62219']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
