control 'SV-250326' do
  title 'Users in the REST API admin role must be authorized.'
  desc 'Users with console access and OS permissions to the folders where the Liberty Server is installed can make changes to the server. In addition, REST API calls that execute server management tasks are available and can be executed remotely. Adding a user to the admin role will allow that user to make changes to the server via the REST API calls.

The admin role must be controlled and users who are in that role must be authorized.'
  desc 'check', 'As a user with access to ${server.config.dir}/server.xml, review the file and look for the admin role settings.

grep -i administrator-role ${server.config.dir}/server.xml
grep -i quickstartsecurity ${server.config.dir}/server.xml

If the admin role has been created, users in that role must be documented and approved. However, using the basic registry or the quickstartsecurity methods are not acceptable. The preferred user registry method is to use a centralized access control method via LDAP. 

If no admin users exist at all, this is not a finding.

If admin users in an LDAP user registry configuration are not documented and approved, this is a finding.

If admin users exist in a basic user registry configuration, or in a quickstartsecurity user configuration, this is a finding.

LDAP EXAMPLE:
<administrator-role>
     <user>cn=bob,o=ibm,c=us</user>
 </administrator-role>

BASIC REGISTRY EXAMPLE:
<basicRegistry>
     <user name="bob" password="bobpassword"/>
     <user name="joe" password="joepassword"/>
     <group name="group1" ...>
     </group>
 </basicRegistry>

<administrator-role>
     <user>bob</user>
     <group>group1</group>
 </administrator-role>

QUICKSTARTSECURITY EXAMPLE:
<featureManager>
     <feature>restConnector-2.0</feature>
 </featureManager>
 <quickStartSecurity userName="bob" userPassword="bobpassword" />
 <keyStore id="defaultKeyStore" password="keystorePassword"/>'
  desc 'fix', 'If an admin user exists in either a basic user registry or a quickstartsecurity registry, edit the ${server.config.dir}/server.xml file and remove the basic registry and/or quickstartsecurity registry settings.

If an admin user exists via an LDAP user registry setting, document and approve the user(s) or group that have been assigned to the admin role and ensure anyone granted REST API admin rights is authorized.

LDAP EXAMPLE:
<administrator-role>
     <user>cn=bob,o=ibm,c=us</user>
 </administrator-role>

BASIC REGISTRY EXAMPLE:
<basicRegistry>
     <user name="bob" password="bobpassword"/>
     <user name="joe" password="joepassword"/>
     <group name="group1" ...>
     </group>
 </basicRegistry>

<administrator-role>
     <user>bob</user>
     <group>group1</group>
 </administrator-role>

QUICKSTARTSECURITY EXAMPLE:
<featureManager>
     <feature>restConnector-2.0</feature>
 </featureManager>
 <quickStartSecurity userName="bob" userPassword="bobpassword" />
 <keyStore id="defaultKeyStore" password="keystorePassword"/>'
  impact 0.7
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53761r795029_chk'
  tag severity: 'high'
  tag gid: 'V-250326'
  tag rid: 'SV-250326r795031_rule'
  tag stig_id: 'IBMW-LS-000050'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-53715r795030_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
