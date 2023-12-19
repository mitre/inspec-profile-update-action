control 'SV-258594' do
  title 'The ICS must be configured to authenticate all clients before establishing a connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For ICS, user authentication uses authentication servers, realms, roles, and sign-in policies. To the device, both machine and user authentication are treated as user logins and certificates (machine certs and CAC) are supported for authentication. Although both machine and human users are considered "users" to the device. The system supports separating admin from user/computer authentication by duplicating auth servers and only associating a single server to an admin realm or a user realm but not both. This supports the DOD best practice of authenticating admin authentication using a separate authentication server from user authentication.'
  desc 'check', %q(Verify client certificates are installed and assigned to applicable user/computer realm to enable client authentication for all remote clients.

In the Ivanti ICS Web UI, navigate to Users >> User Realms >> User Realms.
1. Click the user realm that is currently being used on the ICS for standard remote access VPN logins.
2. In the "General" tab, under Servers >> Authentication, verify it is defined with a certificate authenticate server.
3. In the "General" tab, under Servers >> Directory/Attribute, verify "none" is not displayed.
4. In the "Role Mapping" tab, under "when users meet these conditions", verify "Group" must be used, and the local site's administrator active directory group must be selected and assigned to the role that was created.

If the ICS is not configured to authenticate all client devices before establishing a connection, this is a finding.)
  desc 'fix', %q(Configure client certificates and enable them on an appropriate user/computer realm to enable client authentication.

In the Ivanti ICS Web UI, navigate to System >> Configuration >> Certificates >> Trusted Server CAs.
1. Click "Import Trusted Server CAs".
2. Import the Active Directory root CA certificate by clicking "Browse", selecting the certificate file, and clicking "Import Certificate".
3. Repeat these steps for the intermediate CA certificate.
NOTE: these certificates could be DOD-signed CA certificates, or they could be internal private CA certificates. Import certificates based on the use case of the site.

In the Ivanti ICS Web UI, navigate to System >> Configuration >> Certificates >> Trusted Client CAs.
1. Click "Import CA Certificate".
2. Import the DOD Client CAC root CA certificate by clicking "Browse", selecting the certificate file, and clicking "Import Certificate" (e.g., "DOD Root CA 3").
3. Repeat these steps for the intermediate/issuing CAC CA certificate (e.g., "DOD ID CA 59").
4. Repeat these steps for each intermediate CAC CA certificate.
5. Click the Root CA certificate that was imported.
6. Under client certificate status checking, ensure the following is set:
- Use OCSP with CRL Fallback.
- "Trusted for client Authentication" must be checked.
7. Optionally, if the network the site is in must use a local OCSP repeater/responder, go to OCSP settings. Otherwise, move on to the Device Certificates.
8. Click "OSCP options". Use "Manually Configured" responders.
9. Enter the URL for the primary and backup OCSP responder.
10. Optionally, if the OCSP responder requires request signing and nonce usage, select those here.

In the Ivanti ICS Web UI, navigate to System >> Configuration >> Certificates >> Device Certificates.
1. Click "New CSR".
2. Under Common Name, ensure this has the FQDN for the ICS server, then fill out all other items.
3. If using RSA, select "2048". If using ECC, select "P-384".
IMPORTANT NOTE: If the remote access VPN is carrying classified data, the certificate and key being used by ICS MUST be an ECC P-384 key pair.
4. Click "Create CSR". Export the CSR and import it into the DOD site's Registration Authority (RA). Ensure that Subject Alternative Names (SANs) are created for all FQDNs, server names, and cluster names on the web enrollment form.
5. Once the certificate is approved, download it and import it in this same section of the ICS.

In the Ivanti ICS Web UI, navigate to Authentication >> Auth Servers
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
NOTE: If there are failures in this testing ensure that the step for Device Certificates and Trusted Server CAs were completed, as this will cause LDAPS certificate issues.
18. Under authentication required, click the box for "Authentication required" to search LDAP.
19. Enter the service account's Admin DN using this as an example format: CN=PCS.SVC,OU=IVANTI,DC=DOD,DC=mil
20. Enter the service account's password.
21. Under "Finding user entries", add the base DN of the domain as an example format: DC=DOD,DC=mil
22. Under "filter", use this specific attribute configuration: userPrincipalName=<USER>
23. Under "group membership", add the base DN of where admin users that will access, using this as an example format: OU=IVANTI,DC=DOD,DC=mil
24. Under "filter", use the following: cn=<GROUPNAME>
25. Under "member attribute", use the following: member
26. Click Save "Changes".
27. Now back in the same LDAP server configuration screen, scroll down and click the "Server Catalog" hyperlink.
28. Under "attributes", click "New", Type: userPrincipalName, and click "Save Changes".
29. Under "groups", click "Search". In the search box, type the group name used for admin logins.
30. Check the box next to the group that is found and click "Add Selected".
31. Repeat these steps for all various groups needed for various roles on the ICS system. For example, groups for auditors, ISSOs, NOC, SOC, Viewer, etc.
32. Click "Save Changes".

In the Ivanti ICS Web UI, navigate to Users >> Users Realms.
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
14. Click "Save Changes".

In the Ivanti ICS Web UI, navigate to Authentication >> Sign-in >> Sign-in Policies.
1. Create a New URL or edit the */ URL (depending on the site).
NOTE: it is recommended to create a new sign-in URL until this configuration is fully tested to ensure there is still web UI reachability in the troubleshooting process.
2. Under authentication realm, click the "User picks from a list of authentication realms".
3. Click "Save Changes".

Test and verify the connection with CAC/Alt Token and LDAPS by attempting a remote access VPN web UI login using the token or CAC and entering the sign-in URL. Once successful, the user will click on the ICS client for completing the login connection.)
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62334r930468_chk'
  tag severity: 'medium'
  tag gid: 'V-258594'
  tag rid: 'SV-258594r930470_rule'
  tag stig_id: 'IVCS-VN-000340'
  tag gtitle: 'SRG-NET-000343-VPN-001370'
  tag fix_id: 'F-62243r930469_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
