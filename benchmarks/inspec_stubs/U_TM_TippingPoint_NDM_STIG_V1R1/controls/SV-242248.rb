control 'SV-242248' do
  title 'The TippingPoint SMS must enforce access restrictions associated with changes to device configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to device configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the device can potentially have significant effects on the overall security of the device. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to device components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'In the Trend Micro TippingPoint system, ensure the SMS client is using CAC authentication and LDAPS authorization.

1. Log in to the SMS client. 
2. Navigate to Authentication and Authorization >> Authentication. 

If "Use CAC authentication" is not selected, this is a finding.'
  desc 'fix', %q(Follow these configuration steps to enable CAC/LDAPS authentication and authorization to the Trend Micro TippingPoint SMS client. The Site's LDAPS/AD environment must be configured to audit all account actions.

I. Certificate Load Steps: 
1. Log in to the SMS client. 
2. Select Certificate Management >> CA certificates >> Import. 
3. Find the CA signing certificate bundle for the LDAPS servers on your machine. 
4. Enter the name, then select browse to find the CA certificate.
5. Click OK.
6. Repeat steps for all other DoD Root and Intermediate CAs being used for the administrator’s admin-token/CACs.

II. LDAP Authorization configuration steps: 
1. Select Authentication and Authorization >> Groups >> New.
2. Type the name of the LDAP group exactly as it appears as the CN in the active directory domain. 
3. Add all site-specific details including which role to map superuser, admin, or operator. 
4. Under Active Directory Group Mapping ensure the item "map this group to the same named group in active directory" is selected. 
5. Select OK.

III. LDAPS Server configuration - ensure a DNS resolver has been configured in accordance with the admin guide, and this DNS resolver knows how to resolve the domain the SMS will log into: 
1. Under Admin, navigate to Authentication and CAC >> Edit. 
2. Enter the Server address: ensure it is the fully qualified domain name as the LDAPS certificate will likely have it.
3. Enable SSL: must be checked for LDAPS. 
4. Current certificate: must be the intermediate root certificate/issuing CA certificate for the domain controllers - this is the CA certificate loaded in the first section. 
5. Port: 636 or your DoD LDAPS port, if different.
6. Timeout: 30 seconds is the default.
7. Admin name: the account that has privileges to access the directory schema – format is username@domain.name 
8. Admin password: password of previous admin account. 
9. User search base: this is the LDAP directory tree for the accounts that will be allowed. Example: ou=Trend Micro,dc=dod,dc=disa,dc=mil 
10. User search attribute: normally in DoD this is userPrincipalName.
11. User display attribute: normally in DoD this is sAMAccountName.
12. Group search base: this is the LDAP directory tree for the groups that will be allowed. Example: ou=Trend Micro,dc=dod,dc=disa,dc=mil 
13. Group name attribute: normally it is cn.
14. Select the test button to ensure all configurations provided function correctly. 
15. Select OK.

IV. Enable OCSP revocation checking: 
1. Under OCSP Settings, navigate to Certificate Management and Revocation >> New >> Certificate Authority. 
2. Type the full OCSP URI (e.g. http://ocsp.disa.mil).
3. Repeat this step for all CA certificates in the CAC trust chain.
4. Optionally, to add a CRL click New under Certificate Revocation Lists.
5. Select the Certificate Authority. 
6. Type the full CRL path including to the specific CRL file (e.g. http://crl.disa.mil/certificate.crl).

V. Enable CAC authentication/LDAPS authorization: 
1. Navigate to Admin >> Authentication and Groups >> Edit.
2. Click Use CAC Authentication (ensure the local emergency user account is checked for local access in case of emergency troubleshooting). 
3. Select OK. 
4. Close the SMS client.

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
2. Login with the local account of last resort. 
3. Type the command "set cac.disable = yes" - this will give your local admin login access to the SMS client to troubleshoot any configuration errors.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45523r710749_chk'
  tag severity: 'medium'
  tag gid: 'V-242248'
  tag rid: 'SV-242248r710751_rule'
  tag stig_id: 'TIPP-NM-000420'
  tag gtitle: 'SRG-APP-000380-NDM-000304'
  tag fix_id: 'F-45481r710750_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
