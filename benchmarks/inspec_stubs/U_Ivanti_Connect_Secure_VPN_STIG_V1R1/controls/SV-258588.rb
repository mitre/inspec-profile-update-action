control 'SV-258588' do
  title 'The ICS must be configured to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc "To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following.

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals' in-group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN or proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', 'In the ICS Web UI, navigate to Users >> User Realms >> User Realms.
1. Click the user realm that is currently being used on the ICS for standard remote access VPN logins.
2. View "General" tab, under Servers >> Authentication. Verify a certificate authentication server is configured.
3. View "General" tab, under Servers >> Directory/Attribute. Verify there is an entry defined.
4. View "Role Mapping" tab, under "when users meet these conditions", verify "Group" is used with the local user active directory group selected and assigned to the role that was created.

If the ICS does not use DOD PKI for network access to nonprivileged accounts, this is a finding.'
  desc 'fix', %q(Configure an authentication server for the user realm.

In the ICS Web UI, navigate to Users >> User Realms >> User Realms.
1. Click the user realm that is currently being used on the ICS for standard remote access VPN logins.
2. In the "General" tab, under Servers >> Authentication.
3. Click "New Servers". Under "server type", select Certificate Server >> New Server.
4. Type a Name, then under User Name template type this exactly: <certAttr.altname.UPN>
5. Click "Save Changes".
6. Navigate to Authentication >> Auth Servers.
7. Click "New Servers". Under "server type", select LDAP Server >> New Server.
8. Type a name for the primary LDAP server domain.
9. LDAP server: the FQDN of the server (an IP address may cause an error as the LDAP server certificate might not have an IP in the SAN field).
10. LDAP port: 636 (this is for LDAPS).
11. Backup LDAP Server1: the FQDN of the secondary server (an IP address may cause an error as the LDAP server certificate might not have an IP in the SAN field).
12. Backup LDAP Port1: 636.
13. If a third LDAP server is needed, add this and the port info under Backup LDAP Server2 and Backup LDAP Port2.
14. LDAP Server Type: Active Directory.
15. Connection: LDAPS.
16. Ensure "Validate Server Certificate" is checked.
17. Connection Timeout: 15.
18. Search Timeout: 60.
19. Scroll down to the bottom and click "Save Changes". Click "Test Settings" to ensure valid communications are possible.
NOTE: If there are failures in this testing, ensure that the step for Device Certificates and Trusted Server CAs were completed, as this will cause LDAPS certificate issues.
20. Under "authentication required", click the box for "Authentication required" to search LDAP.
21. Enter the service account's Admin DN using this as an example format: CN=PCS.SVC,OU=IVANTI,DC=DOD,DC=mil
22. Enter the service account's password.
23. Under "Finding user entries", add the base DN of the domain as an example format: DC=DOD,DC=mil
24. Under "filter", use this specific attribute configuration: userPrincipalName=<USER>
25. Under "group membership", add the base DN of where admin users that will access, using this as an example format: OU=IVANTI,DC=DOD,DC=mil
26. Under "filter", use the following: cn=<GROUPNAME>
27. Under "member attribute", use the following: member.
28. Click "Save Changes".
29. In the same LDAP server configuration screen, scroll down and click the "Server Catalog" hyperlink.
30. Under "attributes", click "New", Type: userPrincipalName, and click "Save Changes".
31. Under "groups", click "Search". In the search box, type the group name used for user logins.
32. Check the box next to the group that is found and click "Add Selected".
33. Repeat these steps for all various groups needed for various user/computer roles on the ICS system.
34. Click "Save Changes".)
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62328r930450_chk'
  tag severity: 'medium'
  tag gid: 'V-258588'
  tag rid: 'SV-258588r930452_rule'
  tag stig_id: 'IVCS-VN-000180'
  tag gtitle: 'SRG-NET-000138-VPN-000490'
  tag fix_id: 'F-62237r930451_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
