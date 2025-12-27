control 'SV-75169' do
  title 'Google Search Appliances must provide automated mechanisms for supporting user account management. The automated mechanisms may reside within the application itself or may be offered by the operating system or other infrastructure providing automated account management capabilities.'
  desc "A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. Examples include but are not limited to using automation to take action on multiple accounts designated as inactive, suspended or terminated or by disabling accounts located in non-centralized account stores such as multiple servers.

Enterprise environments make application user account management challenging and complex.  A user management process requiring administrators to manually address account management functions adds risk of potential oversight.

Automated mechanisms may be comprised of differing technologies that when placed together contain an overall automated mechanism supporting an organization's automated account management requirements."
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.

Click Administration >> LDAP Setup.

If valid LDAP information is entered, this is not a finding.'
  desc 'fix', %q(Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.

Click Administration >> LDAP Setup.

Click Create.

In the LDAP Directory Server Address section, enter the following information:
Host - LDAP directory server's host name, which is a fully-qualified domain name or an IPv4 address.
Port number (optional) - the port number where the LDAP server listens for requests.
 
If the LDAP server does not allow anonymous users to search, enter the following user credentials that the search appliance uses when logging into the LDAP server:
Distinguished Name (DN) - A login on the LDAP server to which the search appliance connects to send authentication requests. If the LDAP server supports anonymous binds (authentication requests), the site does not need to specify a DN.

Password (optional) - The password for the DN.

Click Continue.

The search appliance attempts to auto-detect the settings of the LDAP Search Base, the User Search Filter, the Group Search Filter, the Returned group format, and if SSL Support exists and displays what it has detected. The advanced settings appear.

If the LDAP server is used to authenticate administrators to the search appliance, specify the LDAP groups against which they will be authenticated:
Superuser Group - Any member of this group is considered an Admin Console administrator. 
Manager Group - Any member of this group is considered an Admin Console manager.
 
An example of a superuser group name is "GSAAdmins" and an example of a manager group name is "GSAManagers." As shown in these examples, do not specify the entire DN in group names.

Test the LDAP server settings for a potential search user by entering the following information in the LDAP Search User Authentication Test box and clicking Test LDAP Settings:
Username - The user name that enables the search appliance to connect to the LDAP server (relative to the search base).
Password - The password the user name that enables the search appliance to connect to the LDAP server.

Configuring one or more LDAP servers on a search appliance.

Editing an LDAP server configuration.

Deleting an LDAP server configuration.

Notes: Configure LDAP server if possible. LDAP (Lightweight Directory Access Protocol) is used to authenticate users before returning secure search results. When a user connects to the Google Search Appliance and requests a search for secure results, the search appliance asks for credentials from the user. These credentials are then forwarded to the LDAP server for validation. The user can use either LDAP or Kerberos, but not both.)
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61663r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60717'
  tag rid: 'SV-75169r1_rule'
  tag stig_id: 'GSAP-00-000075'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-66397r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
