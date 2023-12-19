control 'SV-104513' do
  title 'Accounts for device management must be configured on the authentication server and not on Symantec ProxySG itself, except for the account of last resort.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Verify that the Symantec ProxySG uses a centrally administered AAA server (LDAP to Active Directory).

1. Log on to the Web Management Console.
2. Click Configuration >> Authentication >> LDAP.
3. Click through the "LDAP Realms", "LDAP DN", "LDAP Search & Groups", "LDAP Objectclasses", and "LDAP General" tabs and ensure that the settings are appropriate for your organization. 

If accounts for device management are not configured on the authentication server or are on the Symantec ProxySG itself, except for the account of last resort, this is a finding.'
  desc 'fix', 'In order to configure the ProxySG to use a centrally administered AAA server (LDAP to Active Directory):

1. Log on to the Web Management Console.
2. Click Configuration >> Authentication >> LDAP.
3. Click "New", provide a name for the realm.
4. Change the "Type of LDAP server" to be "Microsoft Active Directory".
5. Provide an IP address or FQDN for the "Primary Server host" and change the port to 636 for LDAP over TLS.
6. Change the "User attribute type" if your organization uses a different attribute than the sAMAccountName, click "OK".
7. Click on the "LDAP Servers" tab, select "Enable SSL", and confirm the other settings per your organization.
8. Click through the "LDAP DN", "LDAP Search & Groups", "LDAP Objectclasses", and "LDAP General" tabs and ensure that the settings are appropriate for your organization.
9. Click "Apply".
10. To test the configuration, click the "Test Configuration" button under "LDAP Servers", and provide a valid username and password.
11. Still within the "Configuration" tab, click on "Policy", then "Visual Policy Editor" and click "Launch".
12. Click "Policy" and choose "Add Admin Authentication Layer".
13. Give it a name and click "OK".
14. Right-click the "Action" cell and choose "Set".
15. With "AdminAuthenticate1" highlighted, click "Edit".
16. Choose the "Realm" that was created on step 3, and click "OK", click "OK" again.
17. Click "Policy" and choose "Add Admin Access Layer".
18. Give it a name and click "OK".
19. Right-click the "Source" field and click "Set".
20. If a "local realm" exists in the list, highlight it and click "Remove".
21. Click "New", and choose either "User" or "Group" depending on what you wish to accomplish.
22. Provide the user or group name, and ensure that the Authentication Realm from step 3 is selected, and populate the Group/User Base DN and "Full Name" fields as appropriate for your organization. 
23. If you wish to restrict this user/group to specific management services, right-click the "Service" Field, and select "Set", click "New", click "Service Name" then choose the appropriate service name. Repeat for any other specific services you would like to grant access for. Then click "OK".
24. Right-click the "Action" cell, and either choose "read-only" or "read/write" access. 
25. Click "File" and choose "Install Policy on SG Appliance".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94683'
  tag rid: 'SV-104513r1_rule'
  tag stig_id: 'SYMP-NM-000160'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-100801r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
