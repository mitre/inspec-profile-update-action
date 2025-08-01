control 'SV-250334' do
  title 'Basic Authentication must be disabled.'
  desc 'Basic authentication does not use a centralized user store like LDAP. Not using a centralized user store complicates user management tasks and increases the risk that user accounts could remain on the system long after users have moved to their next deployment. Basic Auth also stores user credentials and passwords on the system and creates the potential for an attacker to circumvent strong authentication requirements like multi-factor or certificate based authentication.

Allowing failover to Basic Auth allows the Liberty Server to fall back to basic authentication in the event certificate based authentication methods fail. Configuring the Liberty Server to fall back to basic authentication creates the potential for an attacker to circumvent strong authentication requirements and must be avoided.'
  desc 'check', 'As a privileged user with local file access to the ${server.config.dir}/server.xml file, search the server.xml for the basicRegistry setting.

grep -i basicregistry server.xml

SAMPLE:
<basicRegistry id="basic" realm="BasicRealm">
        <user name="employee0" password="emp0pwd" />
        <user name="employee1" password="emp1pwd" />
        <user name="manager0" password="mgr0pwd" />
        <group name="employeeGroup">
            <member name="employee0" />
            <member name="employee1" />
        </group>
    </basicRegistry>  

If <basicRegistry> settings are defined in server.xml, this is a finding.'
  desc 'fix', 'Delete basicRegistry settings and re-configure the server.xml file to use a centralized LDAP user store. 

SAMPLE:

<featureManager>
<feature>appSecurity-2.0</feature>
<feature>ldapRegistry-3.0</feature>
</featureManager>

<ldapRegistry id="ldap" realm="SampleLdapRealm" host="${ldap.server.name}" port="${ldap.server.port}" ignoreCase="true"
baseDN="${ldap.server.base.dn}"
ldapType="${ldap.vendor.type}"
searchTimeout="8m">
</ldapRegistry>'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53769r795053_chk'
  tag severity: 'medium'
  tag gid: 'V-250334'
  tag rid: 'SV-250334r862980_rule'
  tag stig_id: 'IBMW-LS-000381'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-53723r862979_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
