control 'SV-222407' do
  title 'The application must provide automated mechanisms for supporting account management functions.'
  desc "Enterprise environments make application account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error.

Manual examples include but are not limited to admin staff logging into the system or systems and manually performing step by step actions affecting user accounts that could otherwise be automated.  This does not include any manual steps taken to initiate automated processes or the use of automated systems.

A comprehensive application account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended or terminated or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The application must be configured to automatically provide account management functions and these functions must immediately enforce the organization's current account policy. The automated mechanisms may reside within the application itself or may be offered by the operating system or other infrastructure providing automated account management capabilities. Automated mechanisms may be comprised of differing technologies that when placed together contain an overall automated mechanism supporting an organization's automated account management requirements.

Account management functions include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage."
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify the account management methods, processes and procedures that are used.

If the application is utilizing a centralized authentication mechanism such as Active Directory or LDAP, verify all user account activity is conducted via that solution and no local user accounts that circumvent the automated solution are used.

Determine if automated mechanisms are used when managing application user accounts and taking management action on application user accounts. Automated methods include but are not limited to:

Taking action on accounts that have been determined to be inactive, suspended, terminated, or disabled.

Automated action examples include: deleting such accounts, reactivating accounts in conjunction with a validation or verification process, or sending notifications or reminders to the account holders that their account is about to be disabled or deleted.

Verify the action that is taken is automated and repeatable.

If the account management process is manual in nature, this is a finding.'
  desc 'fix', 'Use automated processes and mechanisms for account management functions.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24077r493129_chk'
  tag severity: 'medium'
  tag gid: 'V-222407'
  tag rid: 'SV-222407r879522_rule'
  tag stig_id: 'APSC-DV-000280'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-24066r493130_fix'
  tag 'documentable'
  tag legacy: ['V-69295', 'SV-83917']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
