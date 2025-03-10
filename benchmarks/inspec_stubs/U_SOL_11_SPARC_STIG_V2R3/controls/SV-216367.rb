control 'SV-216367' do
  title 'The operating system must limit the number of concurrent sessions for each account to an organization-defined number of sessions.'
  desc 'Limiting the number of allowed users and sessions per user can limit risks related to denial of service attacks. The organization may define the maximum number of concurrent sessions for an information system account globally, by account type, by account, or by a combination thereof. 

This requirement addresses concurrent sessions for a single information system account and does not address concurrent sessions by a single user via multiple accounts.'
  desc 'check', "Identify the organizational requirements for maximum number of sessions and which users must be restricted. If there are no requirements to limit concurrent sessions, this item does not apply.

For each user requiring concurrent session restrictions, determine if that user is in the user.[username] project where [username] is the user's account username.

# projects [username] | grep user

If the output does not include the project user.[username], this is a finding.

Determine the project membership for the user.

# projects [username]

If the user is a member of any project other than default, group.[groupname], or user.[username], this is a finding.

Determine whether the max-tasks resource control is enabled properly.

# projects -l user.[username] | grep attribs

If the output does not include the text:

attribs: project.max-tasks=(privileged,[MAX],deny)

where [MAX] is the organization-defined maximum number of concurrent sessions, this is a finding."
  desc 'fix', "Identify the organizational requirements for maximum number of sessions and which users must be restricted. If there are no requirements to limit concurrent sessions, this item does not apply.

The Project Management profile is required.

For each user requiring concurrent session restrictions, add the user to the special user.[username] project where [username] is the user's account username where [MAX] is equal to the organizational requirement.

# pfexec projadd -K 'project.max-tasks=(privileged,[MAX],deny)' user.[username]

Determine the project membership for the user.

# projects [username]

If the user is a member of any projects other than default, group.[groupname], or user.[username], remove that project from the user's account.

The root role is required.

# pfedit /etc/user_attr

Locate the line containing the user's username. Remove any project=[projectname] entries from the fifth field.

# pfedit /etc/project

Locate the line containing the user's username in a project other than default, group.[groupname], or user.[username], and remove the user from the project's entry or entries from the fourth field."
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17603r371189_chk'
  tag severity: 'low'
  tag gid: 'V-216367'
  tag rid: 'SV-216367r603267_rule'
  tag stig_id: 'SOL-11.1-040500'
  tag gtitle: 'SRG-OS-000027'
  tag fix_id: 'F-17601r371190_fix'
  tag 'documentable'
  tag legacy: ['V-48151', 'SV-61023']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
