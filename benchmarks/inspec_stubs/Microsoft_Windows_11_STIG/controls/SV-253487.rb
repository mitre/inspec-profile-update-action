control 'SV-253487' do
  title 'The "Create global objects" user right must only be assigned to Administrators, Service, Local Service, and Network Service.'
  desc %q(Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create global objects" user right can create objects that are available to all sessions, which could affect processes in other users' sessions.)
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Create global objects" user right, this is a finding:

Administrators
LOCAL SERVICE
NETWORK SERVICE
SERVICE'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create global objects" to only include the following groups or accounts:

Administrators
LOCAL SERVICE
NETWORK SERVICE
SERVICE'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56940r829543_chk'
  tag severity: 'medium'
  tag gid: 'V-253487'
  tag rid: 'SV-253487r877392_rule'
  tag stig_id: 'WN11-UR-000050'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56890r829544_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
