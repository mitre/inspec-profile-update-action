control 'SV-242633' do
  title 'The Cisco ISE must be configured to use an external authentication server to authenticate administrators prior to granting administrative access.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device.

Cisco ISE can connect with external identity sources such as Active Directory, LDAP, RADIUS Token, and RSA SecurID servers to obtain user information for authentication and authorization. External identity sources also include certificate authentication profiles that you need for certificate-based authentications.

Configure external authentication to a central AAA identity source. 
 
For accounts that you define in the external identity, you must create a password policy for the external administrator account stores. You can then apply this policy to the external administrator groups that eventually become a part of the external administrator RBAC policy. In addition to providing authentication via an external identity store, your network may also require you to use a Common Access Card (CAC) authentication device.

To configure external authentication, you must:
- Configure password-based authentication using an external identity store.
- Create an external administrator group.
- Configure menu access and data access permissions for the external administrator group.
- Create an RBAC policy for external administrator authentication."
  desc 'check', 'Verify an external authentication identity source is configured.

1. Choose Administration >> System >> Admin Access >> Administrators >> Admin Groups.
2. View the External Group configuration.

If the Cisco ISE is not configured to use an external authentication server to authenticate administrators prior to granting administrative access, this is a finding.'
  desc 'fix', 'Configure external authentication to a central AAA identity source. 

Configure password-based authentication for administrators who authenticate using an external identity store such as Active Directory or LDAP.
1. Choose Administration >> System >> Admin Access >> Authentication.
2. On the Authentication Method tab, select Password Based and choose one of the external identity sources that was previously configured (for example, the Active Directory instance that was created).
3. Configure any other specific password policy settings for administrators who authenticate using an external identity store.
4. Click "Save".

Create an external Active Directory or LDAP administrator group. This ensures that Cisco ISE uses the username that is defined in the external Active Directory or LDAP identity store to validate the administrator username and password that was entered upon login.

Cisco ISE imports the Active Directory or LDAP group information from the external resource and stores it as a dictionary attribute. Specify that attribute as one of the policy elements when it is time to configure the RBAC policy for this external administrator authentication method.

1. Choose Administration >> System >> Admin Access >> Administrators >> Admin Groups.
2. Click "Add".
3. Enter a name and optional description.
4. Choose the "External" radio button.
5. From the External Groups drop-down list box, choose the Active Directory group to map for this external administrator group. Click the "+" sign to map additional Active Directory groups to this external administrator group.
6. Click "Save".

Configure menu access and data access permissions that can be assigned to the external administrator group.

1. Choose Administration >> System >> Admin Access >> Permissions.
2. Click one of the following:
- Menu Access - All administrators who belong to the external administrator group can be granted permission at the
menu or submenu level. The menu access permission determines the menus or submenus that they can access.
- Data Access - All administrators who belong to the external administrator group can be granted permission at the
data level. The data access permission determines the data that they can access.
3.  Specify menu access or data access permissions for the external administrator group.
4.  Click "Save".

In order to configure Cisco ISE to authenticate the administrator using an external identity store and to specify custom menu and data access permissions at the same time, configure a new RBAC policy. This policy must have the external administrator group for authentication and the Cisco ISE menu and data access permissions to manage the external authentication and authorization. 

1. Choose Administration >> System >> Admin Access >> Authorization >> Policy.
2.  Specify the rule name, external administrator group, and permissions. Remember that the appropriate external administrator group must be assigned to the correct administrator user IDs. Ensure the administrator in question is associated with the correct external administrator group.
3.  Click "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45908r714207_chk'
  tag severity: 'medium'
  tag gid: 'V-242633'
  tag rid: 'SV-242633r916111_rule'
  tag stig_id: 'CSCO-NM-000270'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-45865r714208_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
