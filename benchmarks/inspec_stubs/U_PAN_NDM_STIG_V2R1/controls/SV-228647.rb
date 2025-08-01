control 'SV-228647' do
  title 'The Palo Alto Networks security platform must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.  An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.  Of the three authentication protocols on the Palo Alto Networks security platform, only Kerberos is inherently replay-resistant.  If LDAP is selected, TLS must also be used.  If RADIUS is used, the device must be operating in FIPS mode.'
  desc 'check', 'Ask the Administrator which form of centralized authentication server is being used. 
Navigate to the appropriate window to view the configured server(s). 
For RADIUS, go to Device >> Server Profiles >> RADIUS
For LDAP, go to Device >> Server Profiles >> LDAP
For Kerberos, go to Device >> Server Profiles >> Kerberos 

If Kerberos is used, this is a not finding.

If LDAP is used, view the LDAP Server Profile; if the SSL checkbox is not checked, this is a finding.

If RADIUS is used, use the command line interface to determine if the device is operating in FIPS mode. Enter the CLI command "show fips-mode" or the command show fips-cc (for more recent releases).

If FIPS mode is set to "off", this is a finding.'
  desc 'fix', 'To configure the Palo Alto Networks security platform to use an LDAP server with SSL/TLS.
Go to Device >> Server-Profiles >> LDAP
Select "Add" (lower left of window).
Populate the required fields.
Enter the name of the profile in the "Name" field.

In the server box:
Enter the name of the server in the "Name" field.
Enter the IP Address of the server. 
Enter the Port number the firewall should use to connect to the LDAP server (default=389 for LDAP; 636 for LDAP over SSL). 
Enter the LDAP Domain name to prepend to all objects learned from the server. The value entered here depends on the specific deployment. If using Active Directory, enter the NetBIOS domain name, not a FQDN (for example, enter acme, not acme.com). Note that if collecting data from multiple domains, it is necessary to create separate server profiles. If using a global catalog server, leave this field blank.
Select the Type of LDAP server connecting to. The correct LDAP attributes in the group mapping settings will automatically be populated based on the selection.
In the Base field, select the DN that corresponds to the point in the LDAP tree where the firewall is to begin its search for user and group information.
Select (check) the SSL checkbox.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30882r513544_chk'
  tag severity: 'medium'
  tag gid: 'V-228647'
  tag rid: 'SV-228647r513546_rule'
  tag stig_id: 'PANW-NM-000051'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-30859r513545_fix'
  tag 'documentable'
  tag legacy: ['SV-77211', 'V-62721']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
