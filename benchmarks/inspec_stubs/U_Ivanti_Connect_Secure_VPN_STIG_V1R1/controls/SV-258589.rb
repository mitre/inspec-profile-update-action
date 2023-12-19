control 'SV-258589' do
  title 'The ICS must be configured to use multifactor authentication (e.g., DOD PKI) for network access to nonprivileged accounts.'
  desc 'To ensure accountability and prevent unauthenticated access, nonprivileged users must use multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication. Use of password for user remote access for nonprivileged account is not authorized.

Factors include:
(i) Something you know (e.g., password/PIN);
(ii) Something you have (e.g., cryptographic identification device, token); or
(iii) Something you are (e.g., biometric).

A nonprivileged account is any information system account with authorizations of a nonprivileged user.

Network access is any access to a network element by a user (or a process acting on behalf of a user) communicating through a network.

The DOD CAC with DOD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'In the ICS Web UI, navigate to Users >> User Realms >> User Realms.
1. Click the user realm that is currently being used on the ICS for standard remote access VPN logins.
2. View "General" tab, under Servers >> Authentication. Verify a certificate authentication server is configured.
3. View "General" tab, under Servers >> Directory/Attribute. Verify there is an entry defined.
4. View "Role Mapping" tab, under "when users meet these conditions", verify "Group" is used with the local user active directory group selected and assigned to the role that was created.

If the ICS does not use DOD PKI for network access to nonprivileged accounts, this is a finding.'
  desc 'fix', %q(Configure the user realm to use DOD PKI and the site's authentication servers. A sign-in policy is then applied in accordance with the site's access configuration. The focus for this requirement is on the path so the installation of the device certificates is not included.

In the ICS Web UI, navigate to Authentication >> Auth Servers.
1. Click "New Servers". Under "server type", select Certificate Server >> New Server.
2. Type a Name. Under User Name template type this exactly: <certAttr.altname.UPN>
3. Click "Save Changes".
4. Navigate to Authentication >> Auth Servers.
5. Click "New Servers". Under "server type", select LDAP Server >> New Server.
6. Type a name for the primary LDAP server domain.
7. LDAP server: the FQDN of the server (an IP address may cause an error as the LDAP server certificate might not have an IP in the SAN field).
8. LDAP port: 636 (this is for LDAPS).
9. Backup LDAP Server1: the FQDN of the secondary server (an IP address may cause an error as the LDAP server certificate might not have an IP in the SAN field).
10. Backup LDAP Port1: 636.
11. If a third LDAP server is needed, add this and the port info under Backup LDAP Server2 and Backup LDAP Port2.
12. LDAP Server Type: Active Directory.
13. Connection: LDAPS.
14. Ensure Validate Server Certificate is checked.
15. Connection Timeout: 15.
16. Search Timeout: 60.
17. Scroll down to the bottom and click "Save Changes". Click "Test Settings" to ensure valid communications are possible.
NOTE: If there are failures in this testing, ensure that the step for Device Certificates and Trusted Server CAs were completed as this will cause LDAPS certificate issues.
18. Under authentication required, click the box for Authentication required to search LDAP.
19. Enter the service account's Admin DN using this as an example format: CN=PCS.SVC,OU=IVANTI,DC=DOD,DC=mil
20. Enter the service account's password.
21. Under "Finding user entries", add the base DN of the domain as an example format: DC=DOD,DC=mil
22. Under "filter", use this specific attribute configuration: userPrincipalName=<USER>
23. Under "group membership", add the base DN of where admin users that will access, using this as an example format: OU=IVANTI,DC=DOD,DC=mil
24. Under "filter", use the following: cn=<GROUPNAME>
25. Under "member attribute", use the following: member.
26. Click "Save Changes".
27. Now back in the same LDAP server configuration screen, scroll down and click the "Server Catalog" hyperlink.
28. Under "attributes", click "New", Type: userPrincipalName, and click "Save Changes".
29. Under "groups", click "Search". In the search box, type the group name used for user logins.
30. Check the box next to the group that is found and click "Add Selected".
31. Repeat these steps for all various groups needed for various user/computer roles on the ICS system.

In the ICS Web UI, navigate to Users >> Users Realms.
1. Click the user realm being used for remote access VPN logins.
2. Under "servers", go to "Authentication" and select the certificate authentication realm created that included the customized User template of <certAttr.altname.UPN>.
3. Under "Directory/Attribute", select the previously created LDAP server.
4. Check the box for "Enable dynamic policy evaluation".
5. Check both the "Refresh roles" and "refresh resource policies".
6. Click "Save Changes".
7. Go to the "Role Mapping" tab.
8. Click "New Rule".
9. Select "Rule based on Group Membership" and click "Update".
10. Type a name for this rule.
11. Select "is".
12. Type the group name exactly as it appears as the CN LDAP attribute.
13. Select the role needed for these VPN logins.
14. Click "Save Changes".)
  impact 0.7
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62329r930453_chk'
  tag severity: 'high'
  tag gid: 'V-258589'
  tag rid: 'SV-258589r930455_rule'
  tag stig_id: 'IVCS-VN-000190'
  tag gtitle: 'SRG-NET-000140-VPN-000500'
  tag fix_id: 'F-62238r930454_fix'
  tag satisfies: ['SRG-NET-000140-VPN-000500', 'SRG-NET-000342-VPN-001360']
  tag 'documentable'
  tag cci: ['CCI-000766', 'CCI-001954']
  tag nist: ['IA-2 (2)', 'IA-2 (12)']
end
