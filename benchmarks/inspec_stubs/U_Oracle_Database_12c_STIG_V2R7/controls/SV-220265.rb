control 'SV-220265' do
  title 'The system must employ automated mechanisms for supporting Oracle user account management.'
  desc "A comprehensive application account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers.

Enterprise environments make application user account management challenging and complex.  A user management process requiring administrators to manually address account management functions adds risk of potential oversight.

Automated mechanisms may be comprised of differing technologies that when placed together contain an overall automated mechanism supporting an organization's automated account management requirements.

Databases can have large numbers of users in disparate locations and job functions. Automatic account management can help mitigate the risk of human error found in manually managing database access.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible. Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. This requirement applies to cases where it is necessary to have accounts directly managed by Oracle."
  desc 'check', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

If an Oracle feature/product, an OS feature, a third-party product, or custom code is used to automate account management, this is not a finding.

Determine what is the site-defined definition of an acceptably small level of manual account-management activity. If the site has established the definition, documented it, and obtained ISSO-ISSM-AO approval, use that definition. If not, use the following rule of thumb as the definition: No more than 12 such accounts exist or are expected to exist; no more than 100 manual account-management actions (account creation, modification, locking, unlocking, removal, etc.) are expected to occur in the course of a year.

If the amount of account management activity is small, as defined in the preceding paragraph, this is not a finding.

Otherwise, this is a finding.'
  desc 'fix', 'Utilize an Oracle feature/product, an OS feature, a third-party product, or custom code to automate some or all account maintenance functionality.

- - - - -

Roles and Profiles are two Oracle features that should be employed in account management. (Indeed, other requirements mandate the use of Roles.) The following are notes from Oracle on the use of Profiles:

A profile is a named set of resource limits and password parameters that restrict database usage and instance resources for a user. You can assign a profile to each user, and a default profile to all others. Each user can have only one profile, and creating a new one supersedes any earlier one.

Profile resource limits are enforced only when you enable resource limitation for the associated database. Enabling such limitation can occur either before starting up the database (the RESOURCE_LIMIT initialization parameter) or while it is open (using an ALTER SYSTEM statement).

While password parameters reside in profiles, they are unaffected by RESOURCE_LIMIT or ALTER SYSTEM and password management is always enabled.'
  impact 0.7
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21980r822468_chk'
  tag severity: 'high'
  tag gid: 'V-220265'
  tag rid: 'SV-220265r879522_rule'
  tag stig_id: 'O121-C2-001800'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-21972r822469_fix'
  tag 'documentable'
  tag legacy: ['SV-76047', 'V-61557']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
