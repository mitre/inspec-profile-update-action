control 'SV-48533' do
  title 'Unauthorized accounts must not have the Allow log on through Remote Desktop Services user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Allow log on through Remote Desktop Services" user right can access a system through Remote Desktop.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Allow log on through Remote Desktop Services" user right, this is a finding.

Administrators may be granted this user right if Remote Desktop Services is necessary for remote administration.  Restricted Admin mode must be used.  This must be document with the ISSO.
See Microsoft article KB2871997 for patches required to add this function to systems prior to Windows 8.1.

Restricted Admin mode for Remote Desktop Connections can be implemented for each session using a command line switch to start the Remote Desktop Client or through a group policy to enable it for all sessions.

The command line to do this is "mstsc /restrictedadmin".

To enable this with group policy, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Credentials Delegation >> "Restrict delegation of credentials to remote servers" to "Enabled".'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on through Remote Desktop Services" to be defined but containing no entries (blank).

Administrators may be granted this user right if Remote Desktop Services is necessary for remote administration.  Restricted Admin mode must be used.  This must be document with the ISSO.
See Microsoft article KB2871997 for patches required to add this function to systems prior to Windows 8.1.

Restricted Admin mode for Remote Desktop Connections can be implemented for each session using a command line switch to start the Remote Desktop Client or through a group policy to enable it for all sessions.

The command line to do this is "mstsc /restrictedadmin".

To enable this with group policy, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Credentials Delegation >> "Restrict delegation of credentials to remote servers" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-62231r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26473'
  tag rid: 'SV-48533r3_rule'
  tag stig_id: 'WN08-UR-000006'
  tag gtitle: 'Allow log on through Remote Desktop Services'
  tag fix_id: 'F-67147r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
