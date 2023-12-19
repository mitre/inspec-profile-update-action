control 'SV-250333' do
  title 'The WebSphere Liberty Server must use an LDAP user registry.'
  desc 'To ensure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated. This is typically accomplished via the use of a user store which is either local (OS-based) or centralized (LDAP) in nature. Best practice guideline to is to use a centralized enterprise LDAP server.

To ensure support to the enterprise, the authentication must use an enterprise solution.'
  desc 'check', 'As a user with local file access to ${server.config.dir}/server.xml file, verify the LDAP user registry is used to authenticate users. If the LDAP user registry is not defined within server.xml, this is a finding. 

<featureManager>
<feature>appSecurity-2.0</feature>
<feature>ldapRegistry-3.0</feature>
</featureManager>

<ldapRegistry id="ldap" realm="SampleLdapRealm" host="${ldap.server.name}" port="${ldap.server.port}" ignoreCase="true"
baseDN="${ldap.server.base.dn}"
ldapType="${ldap.vendor.type}"
searchTimeout="8m">
</ldapRegistry>'
  desc 'fix', 'To ensure an enterprise user management system is configured to uniquely identify and authenticate users and processes acting on behalf of org users, the server.xml must be configured to use an ldap configuration as follows:

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
  tag check_id: 'C-53768r862976_chk'
  tag severity: 'medium'
  tag gid: 'V-250333'
  tag rid: 'SV-250333r862978_rule'
  tag stig_id: 'IBMW-LS-000380'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-53722r862977_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
