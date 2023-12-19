control 'SV-228673' do
  title 'The Palo Alto Networks security platform must employ centrally managed authentication server(s).'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.

Only the emergency administration account, also known as the account of last resort, can be locally configured on the device.'
  desc 'check', "Ask the Administrator which form of centralized authentication server is being used.  
Navigate to the appropriate window to view the configured server(s). 
For RADIUS, go to Device >> Server Profiles >> RADIUS
For LDAP, go to Device >> Server Profiles >> LDAP
For Kerberos, go to Device >> Server Profiles >> Kerberos 
If there are no servers configured in the window that match the specified form of centralized authentication, this is a finding.

Go to Device >> Authentication Profile.
If no authentication profile exists that match the specified form of centralized authentication, this is a finding.

Go to Device >> Administrators
View each Administrator's account.
If no authentication profile exists that match the specified form of centralized authentication, this is a finding. The only exception is the emergency administration account."
  desc 'fix', 'The device allows three different authentication protocols; RADIUS, LDAP, and Kerberos.  In this explanation, LDAP is used. 
To configure the Palo Alto Networks security platform to use an LDAP server, follow these steps:
Go to Device >> Server-Profiles >> LDAP
Select "Add" (lower left of window).
Populate the required fields.
Enter the name of the profile in the "Name" field.
In the server box,
Enter the name of the server in the "Name" field.
Enter the IP Address of the server. 
Enter the Port number the firewall should use to connect to the LDAP server (default=389 for LDAP; 636 for LDAP over SSL). 
Enter the LDAP Domain name to prepend to all objects learned from the server. The value entered here depends on the specific deployment. If using Active Directory, enter the NetBIOS domain name; not a FQDN (for example, enter acme, not acme.com). Note that if collecting data from multiple domains, it is necessary to create separate server profiles. If using a global catalog server, leave this field blank.
Select the Type of LDAP server connecting to. The correct LDAP attributes in the group mapping settings will automatically be populated based on the selection.
In the Base field, select the DN that corresponds to the point in the LDAP tree where the firewall is to begin its search for user and group information.
Select (check) the SSL checkbox.
Select "OK".

To create an Authentication Profile using the newly created LDAP server, follow these steps:
Go to Device >> Authentication Profile
Select "Add" (lower left of window).
Populate the required fields as needed.
In the Authentication field, select "LDAP".
In the Server Profile field, select the configured LDAP server profile.
In the Login Attribute field, enter “sAMAccountName”. 
Select "OK".

Apply the authentication profile to the Administrator accounts.
Go to Device >> Administrators
Select each configured account or select "Add" (in the bottom-left corner of the pane) to create a new one.
In the "Authentication Profile" field, enter the configured LDAP authentication profile.
Select "OK".
Note: The name of the administrator must match the name of the user in the LDAP server.
Note: The authentication profile should not be applied to the emergency administration account since it has special requirements.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.

Note that the emergency administration account is the only account that is configured locally on the device itself.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30908r513622_chk'
  tag severity: 'medium'
  tag gid: 'V-228673'
  tag rid: 'SV-228673r513624_rule'
  tag stig_id: 'PANW-NM-000136'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-30885r513623_fix'
  tag 'documentable'
  tag legacy: ['SV-77263', 'V-62773']
  tag cci: ['CCI-000366', 'CCI-000366', 'CCI-000372']
  tag nist: ['CM-6 b', 'CM-6 b', 'CM-6 (1)']
end
