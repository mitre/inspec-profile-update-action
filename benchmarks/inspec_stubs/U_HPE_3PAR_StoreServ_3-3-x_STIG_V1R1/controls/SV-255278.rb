control 'SV-255278' do
  title 'The HPE 3PAR OS must be configured for centralized account management functions via LDAP.'
  desc "Enterprise environments make account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other errors.

A comprehensive account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended or terminated, or by disabling accounts located in noncentralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The automated mechanisms may reside within the operating system itself or may be offered by other infrastructure providing automated account management capabilities. Automated mechanisms may be composed of differing technologies that, when placed together, contain an overall automated mechanism supporting an organization's automated account management requirements.

Account management functions include assigning group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example, using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage.

The HPE 3PAR OS supports external account management via communication with LDAP-enabled technologies (OpenLDAP and Active Directory). Configuration is required to establish the external management relationship. Internally defined roles (SUPER, SERVICE, EDIT, BROWSE) are mapped to centrally defined user groups. Administrators attempting to log in are checked first against local accounts (for emergency purposes). If no local account exists, the central account management system is checked. Users that are successfully authenticated, are then checked for membership in the mapped groups to establish their authorization to access the system, if any, and at what role level.

"
  desc 'check', 'Determine if the system is configured for external account management.
Enter the command
"cli% showauthparam"

If the result returns an error, or these fields of the output are not configured, this is a finding.
ldap-server              <ip address of LDAP server> 
ldap-server-hn      <host name of LDAP server>
ldap-type <RHDS | OPEN>

If ldap-type is "MSAD", this requirement is not applicable.

If the resulting Parameters DO NOT include the following group parameters, this is a finding.
groups-dn
group-obj 
group-name-attr

Next, verify that the LDAP authentication is operational by entering the command:
cli%  checkpassword  <username>
Enter the password for <username>

If the username and password used in checkpassword are known to be valid LDAP credentials, and the following text is NOT displayed at the end of the resulting output, this is a finding.

user <username>   is authenticated and authorized

Note: checkpassword will fail even if LDAP is properly configured, if the username and password are not entered correctly.'
  desc 'fix', 'If Active Directory is in use, this requirement is not applicable.

Use this series of commands to configure LDAP:

cli% setauthparam -f ldap-type <type>  where type is RHDS or OPEN.
cli%  setauthparam -f ldap-server        <ldap server IP address>
cli%  setauthparam -f ldap-server-hn    <fully qualified domain name of ldap server, such as ldapserver.thisdomain.com>
cli% setauthparam -f binding            simple
cli% setauthparam -f ldap-StartTLS      require
cli% setauthparam -f groups-dn          ou=Groups,dc=thisdomain,dc=com
cli% setauthparam -f user-dn-base       ou=People,dc=thisdomain,dc=com
cli% setauthparam -f user-attr          uid
cli% setauthparam -f group-obj          groupofuniquenames
cli% setauthparam -f group-name-attr    cn
cli% setauthparam -f member-attr        uniqueMember
cli% setauthparam -f browse-map          <customer-assigned name of browse role>   <customer-assigned name of "browse" group> 
cli% setauthparam -f edit-map          <customer-assigned name of edit role>   <customer-assigned name of "edit" group>
cli% setauthparam -f service-map      <customer-assigned name of service role>   <customer-assigned name of "service" group>
cli% setauthparam -f super-map          <customer-assigned name of super role>   <customer-assigned name of "super" group>'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58951r870151_chk'
  tag severity: 'medium'
  tag gid: 'V-255278'
  tag rid: 'SV-255278r870153_rule'
  tag stig_id: 'HP3P-33-001500'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-58895r870152_fix'
  tag satisfies: ['SRG-OS-000001-GPOS-00001', 'SRG-OS-000104-GPOS-00051', 'SRG-OS-000042-GPOS-00021']
  tag 'documentable'
  tag cci: ['CCI-000015', 'CCI-000135', 'CCI-000764']
  tag nist: ['AC-2 (1)', 'AU-3 (1)', 'IA-2']
end
