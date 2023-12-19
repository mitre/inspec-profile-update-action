control 'SV-220340' do
  title 'MarkLogic Server must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers. Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

The DBMS must be configured to automatically utilize organization-level account management functions and these functions must immediately enforce the organization's current account policy. 

Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements.

MarkLogic Server can be configured so that users are authenticated using an external authentication protocol, such as Lightweight Directory Access Protocol (LDAP), Kerberos, or certificate. These external agents serve as centralized points of authentication or repositories for user information from which authorization decisions can be made.

MarkLogic Server can be configured with multiple external security providers. A user only needs to authenticate with one of them to gain access."
  desc 'check', 'If all accounts are authenticated by the organization-level authentication/access mechanism and not by the MarkLogic, this is not a finding.

If there are any accounts managed by MarkLogic, review the system documentation for justification and approval of these accounts.

If any MarkLogic-managed accounts exist that are not documented and approved, this is a finding.

Check to see if MarkLogic is configured to use External Security from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the click the Security icon in the left tree menu.
2. Click the External Security icon.
3. If no External Security Configuration Object exists, this is a finding.
4. If at least one External Security Configuration Object exists, proceed to check all existing user accounts below.
5. Click the Security icon in the left tree menu.
6. Click the Users icon.
7. Select the user to check. 
8. In the User Configuration window, verify that at least one external name for the user is defined in the External Name section, if no external names are defined and justification/approval does not exists for this account, this is a finding.
9. Repeat for all users.'
  desc 'fix', 'If there are any accounts managed by MarkLogic, update the system documentation for justification and approval of these accounts.

Configure MarkLogic to use External Security from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon in the left tree menu.
2. Click the External Authentication icon.
3. Click the Create tab at the top of the External Authentication Summary window.
4. Complete the External Security Configuration Object for the available organization-level security provider.
5. Click the Security icon in the left tree menu.
6. Click the Users icon.
7. Select the user to fix.
8. In the User Configuration window, enter the external name for the user in the field in the External Name section.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22055r401471_chk'
  tag severity: 'medium'
  tag gid: 'V-220340'
  tag rid: 'SV-220340r622777_rule'
  tag stig_id: 'ML09-00-000200'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-22044r401472_fix'
  tag 'documentable'
  tag legacy: ['SV-110027', 'V-100923']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
