control 'SV-96019' do
  title 'The WebSphere Application Server local file-based user registry must not be used.'
  desc 'WebSphere does not provide direct audit of changes to the built-in file registry. The built-in file registry must not be used to support user logon accounts. Use an LDAP/AD server and manage user accounts centrally.'
  desc 'check', 'Navigate to Security >> Global Security.

Under "User Account Repository" if the "Federated Repositories" is chosen, click on "Configure".

Under "Repositories in the realm", if "o=defaultWIMFileBasedRealm" appears in the "Base Entry" column, this is a finding.'
  desc 'fix', 'Navigate to Security >> Global Security.

Under "User Account Repository", select "Stand alone LDAP" from the "Available realm definitions" drop-down.

Click on "Configure".

Select an existing user from the LDAP directory to be the primary WebSphere admin user.

Identify the type of LDAP server; specify an IP or DNS name for the LDAP Server, and the port used to connect to the LDAP server.

Specify BASE DN.

Specify the BIND DN.

Specify the BIND Password.

Select the "SSL enabled" check box to use secure LDAP.

Click "Apply".

Click "Save".

Go to Global Security.

Select "Standalone LDAP registry" from the "Available realm definitions" drop-down.

Click "Set as current".

Click "Apply".

Click "Save".

Restart the dmgr and synchronize the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81003r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81305'
  tag rid: 'SV-96019r1_rule'
  tag stig_id: 'WBSP-AS-001020'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-88087r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
