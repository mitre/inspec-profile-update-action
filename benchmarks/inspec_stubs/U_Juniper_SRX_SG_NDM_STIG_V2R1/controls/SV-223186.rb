control 'SV-223186' do
  title 'The Juniper SRX Services Gateway must enforce the assigned privilege level for each administrator and authorizations for access to all commands by assigning a login class to all AAA-authenticated users.'
  desc "To mitigate the risk of unauthorized privileged access to the device, administrators must be assigned only the privileges needed to perform the tasked assigned to their roles. 

Although use of an AAA server is required for non-local access for device management, the SRX must also be configured to implement the corresponding privileges upon user login. Each externally authenticated user is assigned a template that maps to a configured login class.

AAA servers are usually configured to send a Vendor Specific Attribute (VSA) to the Juniper SRX. The device uses this information to determine the login class to assign to the authenticated user. Unless a VSA is returned from the AAA server, externally-authenticated users are mapped to the “remote” user by default. Remote user is a special default account in Junos OS. If this default account, or another designated remote user account, is not configured, then only externally-authenticated users with a returned VSA of a local template account are permitted login. If the remote user is configured, all externally-authenticated users without a returned VSA default to the remote user account's configured login class. All externally-authenticated users with a returned VSA inherit the login class configured for each respective template account.

Junos OS provides four built-in login classes: super-user (all permissions), operator (limited permissions), read-only (no change permissions), and unauthorized (prohibits login). Because these classes are not configurable by the system administrator, they should not be used except for the unauthorized class which may be used for the remote user to deterministically prohibit logins from externally-authenticated users without a returned VSA. Therefore, all template user accounts, and the local account of last resort, should use custom, user-defined, login classes.

Externally-authenticated users maintain two account names in Junos OS: the user and login names. The user name is the local template account name and the login name is the authenticated user’s external account name. Junos OS links the names to determine permissions, based upon login class, but uses the external account name for logging. Doing so permits multiple, individually-authenticated users, to be mapped to the same template account, and therefore enforce uniform permissions for each group of administrators, while also attributing any logged changes to the appropriate individual user.

Template accounts are differentiated from local accounts by the presence of an authentication stanza; only the local account of last resort should have an authentication stanza."
  desc 'check', 'Verify all accounts are assigned a user-defined (not built-in) login class with appropriate permissions configured. If the remote user is configured, it may have a user-defined, or the built-in unauthorized login class.

[edit]
show system login

 Junos OS supports groups, which are centrally located snippets of code. This allows common configuration to be applied at one or more hierarchy levels without requiring duplicated stanzas. If there are no login-classes defined at [edit system login], then check for an apply-groups statement and verify appropriate configuration at the [edit groups] level.

[edit]
show groups

If one or more account templates are not defined with an appropriate login class, this is a finding.

If more than one local account has an authentication stanza and is not documented, this is a finding.

Note: Template accounts are differentiated from local accounts by the presence of an authentication stanza.'
  desc 'fix', 'User accounts, including the account of last resort must be assigned to a login class. 

Configure the class parameters and privileges.

[edit]
Set system login class <class name> idle-timeout 10
set system login class <class name> permissions <appropriate permissions>

Commit for the changes to take effect.

Create and configure template user (s).

[edit]
set system login user <template account name> login-class <appropriate class>

Note: Junos does not permit account creation without login-class assignment.

Note: There are 4 pre-defined classes which should not be uses used for <class name>: Super-user, Operator, Read-only, and unauthorized. However, the Unauthorized class may be used for the remote user account to prevent logins from externally-authenticated users when a VSA is not returned from the AAA server.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24859r513251_chk'
  tag severity: 'medium'
  tag gid: 'V-223186'
  tag rid: 'SV-223186r513253_rule'
  tag stig_id: 'JUSX-DM-000025'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-24847r513252_fix'
  tag 'documentable'
  tag legacy: ['SV-80963', 'V-66473']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
