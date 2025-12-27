control 'SV-18391' do
  title 'User rights and advanced user rights settings do not meet minimum requirements.'
  desc 'Inappropriate granting of user and advanced user rights can provide system, administrative, and other high level capabilities not required by the normal user.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. Expand the Security Configuration and Analysis tree view. 

Navigate to Local Policies -> User Rights Assignment. 

Compare the User Rights to the following list. If any accounts are given rights that are not authorized below, this is a finding. 

Access this computer from the network - Administrators

Act as part of the operating system - See separate vulnerability V-1102

Adjust memory quotas for a process - Administrators, Local Service, Network Service

Allow logon through Terminal Services - (None)

Backup files and directories - Administrators

Bypass traverse checking - Administrators, Users

Change the system time - Administrators

Create a pagefile - Administrators

Create a token object - (None)

Create global objects - Administrators, Local Service, Network Service, Service

Create permanent shared objects - (None)

Debug programs - See separate vulnerability V-18010

Deny access to this computer from the network - See separate vulnerability V-1155

Deny logon as a batch job - See separate vulnerability V-26483

Deny logon as a service - See separate vulnerability V-26484

Deny logon locally - See separate vulnerability V-26485

Deny logon through Terminal Services - See separate vulnerability V-26486

Force shutdown from a remote system - Administrators

Generate security audits - Local Service, Network Service

Impersonate a client after authentication - Administrators, Service

Increase scheduling priority - Administrators

Load and unload device drivers - Administrators

Lock pages in memory - (None)

Log on as a batch job - (None)

Log on as a service - Local Service, Network Service

Log on locally - Administrators, Users

Manage auditing and security log - “Auditor’s” Group

Modify firmware environment values - Administrators

Perform volume maintenance tasks - Administrators

Profile single process - Administrators

Profile system performance - Administrators

Remove computer from docking station - Administrators, Users

Replace a process level token - Local Service, Network Service

Restore files and directories - Administrators

Shut down the system - Administrators, Users

Take ownership of files or other objects - Administrators


Note: The Gold Disk will remediate all User Rights EXCEPT “Manage auditing and security log”. It will report any users/groups with this User Right for review since the site can determine what the “Auditors” group will be named. 

Documentable Explanation: Some applications require one or more of these rights to function. Any exception needs to be documented with the IAO. Acceptable forms of documentation include vendor published documents and application owner confirmation.'
  desc 'fix', 'Configure the system to prevent accounts from having unauthorized User Rights.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-44148r5_chk'
  tag severity: 'medium'
  tag gid: 'V-1103'
  tag rid: 'SV-18391r2_rule'
  tag gtitle: 'User Rights Assignments'
  tag fix_id: 'F-5747r1_fix'
  tag potential_impacts: 'Arbitrarily removing application accounts from certain User Rights may cause the applications to cease functioning.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECLP-1'
end
