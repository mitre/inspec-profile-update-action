control 'SV-18394' do
  title 'User rights assignments must meet minimum requirements.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities not required by the normal user.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

Compare the User Rights to the following list. If any groups or accounts are given rights that are not authorized below, this is a finding.

Access Credential Manager as a trusted caller - (None)

Access this computer from the network - Administrators, Authenticated Users, Enterprise Domain Controllers

Act as part of the operating system - See separate requirement V-1102

Add workstations to domain - Administrators

Allow log on locally - Administrators

Allow log on through Terminal Services - Administrators

Backup files and directories - Administrators

Bypass traverse checking - Administrators, Authenticated Users, Local Service, Network Service

Change the system time - Administrators, Local Service

Change the time zone - Administrators, Local Service

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

Enable computer and user accounts to be trusted for delegation - Administrators

Force shutdown from a remote system - Administrators

Generate security audits - Local Service, Network Service

Impersonate a client after authentication - Administrators, Service, Local Service, Network Service

Increase scheduling priority - Administrators

Load and unload device drivers - Administrators

Lock pages in memory - (None)

Manage auditing and security log - Administrators; plus Exchange Enterprise Servers Group on Exchange Servers
If the organization has an "Auditors" group from previous requirements, the assignment of this group to the user right would not be a finding.

Modify an object label - Administrators

Modify firmware environment values - Administrators

Perform volume maintenance tasks - Administrators

Profile single process - Administrators

Profile system performance - Administrators

Remove computer from docking station - Administrators

Replace a process level token - Local Service, Network Service

Restore files and directories - Administrators

Shut down the system - Administrators

Synchronize directory service data - See separate requirement V-12780

Take ownership of files or other objects - Administrators

Documentable Explanation: Some applications require one or more of these rights to function. Any exception needs to be documented with the ISSO. Acceptable forms of documentation include vendor published documents and application owner confirmation.'
  desc 'fix', 'Configure the policy values for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> as listed below:

Access Credential Manager as a trusted caller - (None)

Access this computer from the network - Administrators, Authenticated Users, Enterprise Domain Controllers

Act as part of the operating system - See separate requirement V-1102

Add workstations to domain - Administrators

Allow log on locally - Administrators

Allow log on through Terminal Services - Administrators

Backup files and directories - Administrators

Bypass traverse checking - Administrators, Authenticated Users, Local Service, Network Service

Change the system time - Administrators, Local Service

Change the time zone - Administrators, Local Service

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

Enable computer and user accounts to be trusted for delegation - Administrators

Force shutdown from a remote system - Administrators

Generate security audits - Local Service, Network Service

Impersonate a client after authentication - Administrators, Service, Local Service, Network Service

Increase scheduling priority - Administrators

Load and unload device drivers - Administrators

Lock pages in memory - (None)

Manage auditing and security log - Administrators; plus Exchange Enterprise Servers Group on Exchange Servers
If the organization has an "Auditors" group from previous requirements, the assignment of this group to the user right would not be a finding.

Modify an object label - Administrators

Modify firmware environment values - Administrators

Perform volume maintenance tasks - Administrators

Profile single process - Administrators

Profile system performance - Administrators

Remove computer from docking station - Administrators

Replace a process level token - Local Service, Network Service

Restore files and directories - Administrators

Shut down the system - Administrators

Synchronize directory service data - See separate requirement V-12780

Take ownership of files or other objects - Administrators'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-72735r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1103'
  tag rid: 'SV-18394r4_rule'
  tag stig_id: '4.010-DC'
  tag gtitle: 'User Rights Assignments'
  tag fix_id: 'F-78927r2_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
