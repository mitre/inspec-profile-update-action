control 'SV-213528' do
  title 'The JBoss server must be configured to use individual accounts and not generic or shared accounts.'
  desc 'To assure individual accountability and prevent unauthorized access, application server users (and any processes acting on behalf of application server users) must be individually identified and authenticated.

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users.

Application servers must ensure that individual users are authenticated prior to authenticating via role or group authentication. This is to ensure that there is non-repudiation for actions taken.'
  desc 'check', 'If the application server management interface is configured to use LDAP authentication this requirement is NA.

Determine the mode in which the JBoss server is operating by authenticating to the OS, changing to the <JBOSS_HOME>/bin/ folder and executing the jboss-cli script.
Connect to the server and authenticate.
Run the command: "ls" and examine the "launch-type" setting.

User account information is stored in the following files for a JBoss server configured in standalone mode.  The command line flags passed to the "standalone" startup script determine the standalone operating mode:
<JBOSS_HOME>/standalone/configuration/standalone.xml
<JBOSS_HOME>/standalone/configuration/standalone-full.xml
<JBOSS_HOME>/standalone/configuration/standalone.-full-ha.xml
<JBOSS_HOME>/standalone/configuration/standalone.ha.xml

For a Managed Domain:
<JBOSS_HOME>/domain/configuration/domain.xml.

Review both files for generic or shared user accounts.

Open each xml file with a text editor and locate the <management-interfaces> section.
Review the <user name = "xxxxx"> sub-section where "xxxxx" will be a user name.

Have the system administrator identify the user of each user account.

If user accounts are not assigned to individual users, this is a finding.'
  desc 'fix', 'Configure the application server so required users are individually authenticated by creating individual user accounts.  Utilize an LDAP server that is configured according to DOD policy.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14751r296250_chk'
  tag severity: 'medium'
  tag gid: 'V-213528'
  tag rid: 'SV-213528r615939_rule'
  tag stig_id: 'JBOS-AS-000275'
  tag gtitle: 'SRG-APP-000153-AS-000104'
  tag fix_id: 'F-14749r296251_fix'
  tag 'documentable'
  tag legacy: ['SV-76771', 'V-62281']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
