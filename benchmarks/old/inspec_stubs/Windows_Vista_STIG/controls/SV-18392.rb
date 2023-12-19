control 'SV-18392' do
  title 'User rights assignments must meet minimum requirements.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities not required by the normal user.'
  desc 'fix', 'Configure the policy values for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> as listed below:

Access this computer from the network - Administrators

Act as part of the operating system - See separate requirement V-1102

Adjust memory quotas for a process - Administrators, Local Service, Network Service

Allow log on locally - Administrators, Users

Allow log on through Terminal Services - (None)

Backup files and directories - Administrators

Bypass traverse checking - Administrators, Users, Local Service, Network Service

Change the system time - Administrators, Local Service

Change the time zone - Administrators, Users, Local Service

Create a pagefile - Administrators

Create a token object - (None)

Create global objects - Administrators, Service, Local Service, Network Service

Create permanent shared objects - (None)

Create symbolic links - Administrators

Debug programs - See separate requirement V-18010

Deny access to this computer from the network - See separate requirement V-1155

Deny log on as a batch job - See separate requirement V-26483

Deny log on as a service - See separate requirement V-26484

Deny log on locally - See separate requirement V-26485

Deny log on through Terminal Services - See separate requirement V-26486

Enable computer and user accounts to be trusted for delegation - (None)

Force shutdown from a remote system - Administrators

Generate security audits - Local Service, Network Service

Impersonate a client after authentication - Administrators, Service, Local Service, Network Service

Increase a process working set - Administrators, Local Service

Increase scheduling priority - Administrators

Load and unload device drivers - Administrators

Lock pages in memory - (None)

Log on as a batch job - (None)

Log on as a service - (None)

Manage auditing and security log - Administrators
If the organization has an "Auditors" group from previous requirements, the assignment of this group to the user right would not be a finding.

Modify an object label - (None)

Modify firmware environment values - Administrators

Perform volume maintenance tasks - Administrators

Profile single process - Administrators

Profile system performance - Administrators

Remove computer from docking station - Administrators, Users

Replace a process level token - Local Service, Network Service

Restore files and directories - Administrators

Shut down the system - Administrators, Users

Take ownership of files or other objects - Administrators'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1103'
  tag rid: 'SV-18392r3_rule'
  tag gtitle: 'User Rights Assignments'
  tag fix_id: 'F-67155r2_fix'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
