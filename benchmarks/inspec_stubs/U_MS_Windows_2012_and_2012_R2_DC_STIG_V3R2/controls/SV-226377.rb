control 'SV-226377' do
  title 'The Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service.'
  desc %q(Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create global objects" user right can create objects that are available to all sessions, which could affect processes in other users' sessions.)
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Create global objects" user right, this is a finding:

Administrators
Service
Local Service
Network Service

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create global objects" to only include the following accounts or groups:

Administrators
Service
Local Service
Network Service'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28080r476977_chk'
  tag severity: 'medium'
  tag gid: 'V-226377'
  tag rid: 'SV-226377r569184_rule'
  tag stig_id: 'WN12-UR-000013'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28068r476978_fix'
  tag 'documentable'
  tag legacy: ['SV-52114', 'V-26480']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
