control 'SV-242254' do
  title 'The TippingPoint SMS must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access and to enforce access restrictions.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device.

"
  desc 'check', 'Configure the Trend Micro TippingPoint system to ensure the SMS client is using CAC authentication and LDAPS authorization.

1. Log in to the SMS client.
2. Click on Authentication and Authorization.
3. Click authentication.
4. Ensure "Use CAC authentication" is currently selected. 

If the TippingPoint SMS is not configured to use an authentication server for the purpose of authenticating users prior to granting administrative access, this is a finding.'
  desc 'fix', %q(Follow these configuration steps to enable CAC/LDAPS authentication and authorization to the Trend Micro TippingPoint SMS client. The Site's LDAPS/AD environment must be configured to audit all account actions.

I. Certificate Load Steps: 
1. Log in to the SMS client. 
2. Select certificate management. 
3. Click CA certificates. 
4. Select import. 
5. Find the CA signing certificate bundle for the LDAPS servers on your machine. 
6. Enter the name, then select browse to find the CA certificate.
7. Click OK.
8. Repeat steps for all other DoD Root and Intermediate CAs being used for the administrator’s admin-token/CACs.

II. LDAP Authorization configuration steps: 
1. Click Authentication and Authorization.
2. Select Groups. 
3. Click New.
4. Type the name of the LDAP group exactly as it appears as the CN in the active directory domain. 
5. Add all site-specific details including which role to map superuser, admin, or operator. 
6. Under Active Directory Group Mapping ensure the item "map this group to the same named group in active directory" is selected. 
7. Select OK.

III. LDAPS Server configuration - ensure a DNS resolver has been configured in accordance with the admin guide, and this DNS resolver knows how to resolve the domain the SMS will log into: 
1. Under Admin, click Authentication and CAC.
2. Click edit. 
3. Enter the Server address: ensure it is the fully qualified domain name as the LDAPS certificate will likely have it.
4. Enable SSL: must be checked for LDAPS. 
5. Current certificate: must be the intermediate root certificate/issuing CA certificate for the domain controllers - this is the CA certificate loaded in the first section. 
6. Port: 636 (or if your DoD LDAPS port is different add this).
7. Timeout: 30 seconds is the default.
8. Admin name: this must be the account that has privileges to access the directory schema – format is username@domain.name.
9. Admin password: password of previous admin account. 
10. User search base: this is the LDAP directory tree for the accounts that will be allowed. Example: ou=Trend Micro,dc=dod,dc=disa,dc=mil 
11. User search attribute: normally in DoD this is userPrincipalName.
12. User display attribute: normally in DoD this is sAMAccountName.
13. Group search base: this is the LDAP directory tree for the groups that will be allowed. Example: ou=Trend Micro,dc=dod,dc=disa,dc=mil 
14. Group name attribute: normally it is cn.
15. Select the test button to ensure all configurations provided function correctly. 
16. Select OK.

IV. Enable OCSP revocation Checking: 
1. Select Certificate Management and Revocation.
2. Click New under OCSP Settings.
3. Select the Certificate Authority. Type the full OCSP URI (e.g. http://ocsp.disa.mil).
4. Repeat this step for all CA certificates in the CAC trust chain.
5. Optionally, to add a CRL click New under Certificate Revocation Lists. 
6. Select the Certificate Authority. 
7. Type the full CRL path including to the specific CRL file (e.g. http://crl.disa.mil/certificate.crl).

V. Enable CAC authentication/LDAPS authorization: 
1. Click Admin, click Authentication and Groups.
2. Select Edit.
3. Click Use CAC Authentication (ensure the local emergency user account is checked for local access in case of emergency troubleshooting). 
4. Select OK. 
5. Close the SMS client.

VI. Test CAC authentication: 
1. Ensure one other smartcard reader is enabled in the device manager of the computer you are using. 
2. Open the SMS client. 
3. Type the hostname/IP of the SMS server.
4. Ensuring the CAC/admin token is inserted in the reader, type the PIN of the CAC. 
5. Select the certificate to use to login.
6. Select OK. 
7. User should be taken to the dashboard and configuration area of the SMS.

VII. Troubleshooting: 
1. If you receive errors logging in with CAC go to the serial console of the SMS server. 
2. Login with the local emergency user account. 
3. Type the command "set cac.disable = yes" - this will give your local admin login access to the SMS client to troubleshoot any configuration errors.

VIII. Ensure the site's LDAP/Active Directory infrastructure is reconfigured to audit account creation, modification, disabling, and removals.)
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45529r710767_chk'
  tag severity: 'high'
  tag gid: 'V-242254'
  tag rid: 'SV-242254r754442_rule'
  tag stig_id: 'TIPP-NM-000570'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-45487r710768_fix'
  tag satisfies: ['SRG-APP-000516-NDM-000336', 'SRG-APP-000516-NDM-000335', 'SRG-APP-000033-NDM-000212', 'SRG-APP-000038-NDM-000213', 'SRG-APP-000153-NDM-000249', 'SRG-APP-000329-NDM-000287 SRG-APP-000156-NDM-000250', 'SRG-APP-000340-NDM-000288', 'SRG-APP-000380-NDM-000304', 'SRG-APP-000408-NDM-000314']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000345', 'CCI-000366', 'CCI-000370', 'CCI-000770', 'CCI-001368', 'CCI-002169', 'CCI-001813', 'CCI-001941', 'CCI-002235', 'CCI-002883']
  tag nist: ['AC-3', 'CM-5', 'CM-6 b', 'CM-6 (1)', 'IA-2 (5)', 'AC-4', 'AC-3 (7)', 'CM-5 (1) (a)', 'IA-2 (8)', 'AC-6 (10)', 'MA-3 (4)']
end
