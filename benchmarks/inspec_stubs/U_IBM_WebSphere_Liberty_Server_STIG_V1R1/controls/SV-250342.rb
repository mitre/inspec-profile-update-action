control 'SV-250342' do
  title 'Users in a reader-role must be authorized.'
  desc 'The reader role is a management role that allows read-only access to select administrative REST APIs as well as the Admin Center UI (adminCenter-1.0). Preventing non-privileged users from viewing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Users granted reader role access must be authorized.'
  desc 'check', 'As a user with access to the ${server.config.dir}/server.xml file. Review the contents and identify if users have been granted the reader-role.

grep -i reader-role ${server.config.dir}/server.xml

If the reader-role has been created, users in that role must be documented and approved. 

If users in the reader-role are not approved, this is a finding.

EXAMPLE:
<featureManager><feature>appSecurity-3.0</feature></featureManager> 

<reader-role>
<group>group</group>
<group-access-id>group:realmName/groupUniqueId</group-access-id>
<user>user</user>
<user-access-id>user:realmName/userUniqueId</user-access-id>
</reader-role>'
  desc 'fix', 'Edit the ${server.config.dir}/server.xml file. If unauthorized users have been added to the reader-role, remove those users. 

Otherwise, document the users who are granted the reader-role access.

To allow read-only access to select administrative REST APIs, the ${server.config.dir}/server.xml must be configured as follows. Additionally, the users and groups they are a part of must be defined within LDAP.

EXAMPLE:
<featureManager>
<feature>appSecurity-3.0</feature>
</featureManager> 

<reader-role>
<group>group</group><group-access-id> group:realmName/groupUniqueId</group-access-id><user>user</user><user-access-id>user:realmName/userUniqueId</user-access-id>
</reader-role>

<ldapRegistry id="ldap" realm="SampleLdapRealm" host="${ldap.server.name}" port="${ldap.server.port}" ignoreCase="true"
baseDN="${ldap.server.base.dn}"
ldapType="${ldap.vendor.type}"
searchTimeout="8m">
</ldapRegistry>'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53777r795077_chk'
  tag severity: 'medium'
  tag gid: 'V-250342'
  tag rid: 'SV-250342r795079_rule'
  tag stig_id: 'IBMW-LS-000790'
  tag gtitle: 'SRG-APP-000340-AS-000185'
  tag fix_id: 'F-53731r795078_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
