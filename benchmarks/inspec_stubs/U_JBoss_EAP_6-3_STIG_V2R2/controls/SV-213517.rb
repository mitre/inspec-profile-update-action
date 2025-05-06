control 'SV-213517' do
  title 'mgmt-users.properties file permissions must be set to allow access to authorized users only.'
  desc 'The mgmt-users.properties file contains the password hashes of all users who are in a management role and must be protected.  Application servers have the ability to specify that the hosted applications utilize shared libraries. The application server must have a capability to divide roles based upon duties wherein one project user (such as a developer) cannot modify the shared library code of another project user. The application server must also be able to specify that non-privileged users cannot modify any shared library code at all.'
  desc 'check', 'The mgmt-users.properties files are located in the standalone or domain configuration folder.

<JBOSS_HOME>/domain/configuration/mgmt-users.properties.
<JBOSS_HOME>/standalone/configuration/mgmt-users.properties.

Identify users who have access to the files using relevant OS commands.

Obtain documentation from system admin identifying authorized users.

Owner can be full access.
Group can be full access.
All others must have execute permissions only.

If the file permissions are not configured so as to restrict access to only authorized users, or if documentation that identifies authorized users is missing, this is a finding.'
  desc 'fix', 'Configure the file permissions to allow access to authorized users only.
Owner can be full access.
Group can be full access.
All others must have execute permissions only.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14740r296217_chk'
  tag severity: 'medium'
  tag gid: 'V-213517'
  tag rid: 'SV-213517r615939_rule'
  tag stig_id: 'JBOS-AS-000210'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag fix_id: 'F-14738r296218_fix'
  tag 'documentable'
  tag legacy: ['SV-76749', 'V-62259']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
