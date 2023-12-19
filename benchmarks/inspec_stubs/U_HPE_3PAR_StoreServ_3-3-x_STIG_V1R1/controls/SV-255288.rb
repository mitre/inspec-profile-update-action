control 'SV-255288' do
  title 'The HPE 3PAR OS must provide automated mechanisms for supporting account management functions via AD.'
  desc "Enterprise environments make account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other errors.

A comprehensive account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended or terminated, or by disabling accounts located in noncentralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The automated mechanisms may reside within the operating system itself or may be offered by other infrastructure providing automated account management capabilities. Automated mechanisms may be composed of differing technologies that, when placed together, contain an overall automated mechanism supporting an organization's automated account management requirements.

Account management functions include: Assigning group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: Using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage.

The HPE 3PAR OS supports external account management via communication with LDAP-enabled technologies (OpenLDAP and Active Directory). Configuration is required to establish the external management relationship. Internally defined roles (SUPER, SERVICE, EDIT, BROWSE) are mapped to centrally defined user groups. Administrators attempting to log in are checked first against local accounts (for emergency purposes). If no local account exists, the central account management system is checked. Users that are successfully authenticated, are then checked for membership in the mapped groups to establish their authorization to access the system, if any, and at what role level.

"
  desc 'check', 'Check with the Information Owner to verify if Active Directory will be used for Centralized Account Management.

If Active Directory will not be used, this requirement is not applicable.

Determine if the system is configured for Active Directory (AD). 

Enter the command:
cli% showauthparam

If the result returns an error, or these fields of the output are not configured, this is a finding.
ldap-server              <ip address of AD server> 
ldap-server-hn      <host name of AD server>

If the resulting Parameters include: group parameters
groups-dn
group-obj
group-name-attr
this requirement is not applicable.

Next, verify that the AD authentication is operational by entering the command
cli%  checkpassword  <username>
Enter the password for <username>

If the username and password used in checkpassword are known to be valid AD credentials, and the following text is NOT displayed at the end of the resulting output, this is a finding:

user <username>   is authenticated and authorized

Note: checkpassword will fail even if AD is properly configured, if the username and password are not entered correctly.'
  desc 'fix', 'Use this series of commands to configure AD:

cli% setauthparam -f ldap-type MSAD
cli%  setauthparam -f ldap-server        <AD server IP address>
cli% setauthparam -f binding            simple
cli% setauthparam -f ldap-StartTLS      require
cli% setauthparam -f kerberos-realm    <kerberos realm, such as  WIN2K12FOREST.THISDOMAIN.COM>
cli% setauthparam -f ldap-server-hn     <fully qualified domain name of AD server, such as adserver.thisdomain.com>
cli% setauthparam -f accounts-dn        CN=Users,DC=win2k12forest,DC=thisdomain,DC=com
cli% setauthparam -f user-dn-base       CN=Users,DC=win2k12forest,DC=thisdomain,DC=com
cli% setauthparam -f user-attr          WIN2K12FOREST\\\\
cli% setauthparam -f account-obj        user
cli% setauthparam -f account-name-attr  sAMAccountName
cli% setauthparam -f memberof-attr      memberOf
cli% setauthparam -f browse-map         "CN=<customer-assigned name of browse role>,CN=Users,DC=win2k12forest,DC=thisdomain,DC=com"
cli% setauthparam -f edit-map           "CN=<customer-assigned name of edit role>,CN=Users,DC=win2k12forest,DC=thisdomain,DC=com"
cli% setauthparam -f service-map        "CN=<customer-assigned name of service role>,CN=Users,DC=win2k12forest,DC=thisdomain,DC=com"
cli% setauthparam -f super-map          "CN=<customer-assigned name of super role>,CN=Users,DC=win2k12forest,DC=thisdomain,DC=com"'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58961r870181_chk'
  tag severity: 'medium'
  tag gid: 'V-255288'
  tag rid: 'SV-255288r870183_rule'
  tag stig_id: 'HP3P-33-101500'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-58905r870182_fix'
  tag satisfies: ['SRG-OS-000001-GPOS-00001', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000104-GPOS-00051']
  tag 'documentable'
  tag cci: ['CCI-000015', 'CCI-000135', 'CCI-000764']
  tag nist: ['AC-2 (1)', 'AU-3 (1)', 'IA-2']
end
