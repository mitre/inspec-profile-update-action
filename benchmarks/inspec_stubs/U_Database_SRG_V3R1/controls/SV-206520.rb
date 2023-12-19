control 'SV-206520' do
  title 'The DBMS must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers. Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

The DBMS must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 

Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', 'If all accounts are authenticated by the organization-level authentication/access mechanism and not by the DBMS, this is not a finding.

If there are any accounts managed by the DBMS, review the system documentation for justification and approval of these accounts.

If any DBMS-managed accounts exist that are not documented and approved, this is a finding.'
  desc 'fix', 'Integrate DBMS security with an organization-level authentication/access mechanism providing account management for all users, groups, roles, and any other principals.

For each DBMS-managed account that is not documented and approved, either transfer it to management by the external mechanism, or document the need for it and obtain approval, as appropriate.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6780r291228_chk'
  tag severity: 'medium'
  tag gid: 'V-206520'
  tag rid: 'SV-206520r617447_rule'
  tag stig_id: 'SRG-APP-000023-DB-000001'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-6780r291229_fix'
  tag 'documentable'
  tag legacy: ['SV-42509', 'V-32192']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
