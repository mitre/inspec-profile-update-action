control 'SV-86145' do
  title 'The CA API Gateway must employ RADIUS + LDAPS or LDAPS to centrally manage authentication settings.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.

Use of RADIUS + LDAPS or LDAPS for authentication and authorization provides the Gateway with an ability to authenticate credentials against a centralized and secured identity management system. This allows permissions for administration of the Gateway to be governed independently of the Gateway.'
  desc 'check', 'Review the CA API Gateway configuration to determine if RADIUS + LDAPS or LDAPS is employed to centrally manage authentication settings.

- SSH to SSG as a member of ssgconfig.
- Select: 1) Configure system settings, 6) Export configuration.
- Export configuration to "file".
- Go back to main menu, select 3) Use a privileged shell (root).
- Navigate to /home/ssgconfig, open "file".
- Check "authenticationType".

If "authenticationType" is not RADIUS_WITH_LDAP or RADIUS_WITH_LDAPS, this is a finding.'
  desc 'fix', %q(Configure the CA API Gateway to employ RADIUS + LDAPS or LDAPS to centrally manage authentication settings.

Prerequisites:

- RADIUS server (for the RADIUS+LDAPS configuration)
- LDAPS server with posixAccount objects for user logins
- LDAPS server CA certificate available via HTTP at a specific URL
- LDAP account for the SSG to bind and lookup info
- posixUser object within LDAP contain object (OU)
- All SSG LDAP posixAccount objects are filtered either by a fixed gidNumber or by membership in an LDAP group containing a sequence of memberUid attributes, one for each user.

Configure SSG to use LDAPS.

- SSH to SSG as a member of ssgconfig
- Select: 1) Configure system settings, 4) Configure authentication method.
- Select: 2) ldap.
- Walk through configuration steps, providing requisite information ensuring:
  - Select LDAPS (secure) "y".
  - Select the appropriate TLS port (636 is the default).
  - Disable anonymous bind.
  - Specify the URL containing the PEM of the CA certificate to download.
  - Specify that the SSG LDAP client "demand" the server's certificate.
  - Set the user filter to use either a specific gidNumber or a group DN.
  - Set the posixAccount attribute to use as login name (uid).

Confirmation configuration should be approximately:

Authentication Type: LDAP_ONLY

Label                                     | Value                                            
---------------------------------------------------------------------------------------------
Secure                                    | true                                             
ActiveDirectory                           | false                                            
Server                                    | smldap.l7tech.com                                
BaseDn                                    | dc=l7tech,dc=com                                 
Port                                      | 636                                              
AnonymousBind                             | false                                            
BindDn                                    | cn=Manager,dc=l7tech,dc=com                      
BindPassword                              | <Hidden>                                         
Object for finding the password for users | ou=posixAccounts                                 
Object class name of users in the LDAP    | posixAccount                                     
Server CaCert File                        | /etc/openldap/cacerts/ldapcacert                 
Certificate Action                        | DEMAND                                           
GroupDn                                   | cn=ssgconfig_ldap,ou=posixGroups,dc=l7tech,dc=com
PAM login attribute                       | uid                                              

Finally, apply configuration and restart the SSG.

Configure SSG to use RADIUS+LDAPS.

- SSH to SSG as ssgconfig.
- Select: 1) Configure system settings, 4) Configure authentication method.
- Select: 4) ldap_radius.
- Walk through configuration steps, providing requisite information ensuring:
  - Enter the RADIUS server's address and secret.
  - Complete the LDAP questions as for the LDAPS only case (above).

Confirmation configuration should be approximately:

Authentication Type: RADIUS_WITH_LDAP

Label   | Value                
-------------------------------
Server  | freerad217.l7tech.com
Secret  | <Hidden>             
Timeout | 3                    

Label                                     | Value                                            
---------------------------------------------------------------------------------------------
Secure                                    | true                                             
ActiveDirectory                           | false                                            
Server                                    | smldap.l7tech.com                                
BaseDn                                    | dc=l7tech,dc=com                                 
Port                                      | 636                                              
AnonymousBind                             | false                                            
BindDn                                    | cn=Manager,dc=l7tech,dc=com                      
BindPassword                              | <Hidden>                                         
Object for finding the password for users | ou=posixAccounts                                 
Object class name of users in the LDAP    | posixAccount                                     
Server CaCert Url                         | http://localhost:8080/cert                       
Certificate Action                        | DEMAND                                           
GroupDn                                   | cn=ssgconfig_ldap,ou=posixGroups,dc=l7tech,dc=com
PAM login attribute                       | uid)
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71521'
  tag rid: 'SV-86145r1_rule'
  tag stig_id: 'CAGW-DM-000110'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-77841r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
