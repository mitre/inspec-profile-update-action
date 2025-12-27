control 'SV-253484' do
  title 'The "Change the system time" user right must only be assigned to Administrators and Local Service and NT SERVICE\\autotimesvc.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Change the system time" user right can change the system time, which can impact authentication, as well as affect time stamps on event log entries.

The NT SERVICE\\autotimesvc is added in v1909 cumulative update.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Change the system time" user right, this is a finding:

Administrators
LOCAL SERVICE'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Change the system time" to only include the following groups or accounts:

Administrators
LOCAL SERVICE'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56937r829534_chk'
  tag severity: 'medium'
  tag gid: 'V-253484'
  tag rid: 'SV-253484r829536_rule'
  tag stig_id: 'WN11-UR-000035'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56887r829535_fix'
  tag 'documentable'
  tag cci: ['CCI-002205']
  tag nist: ['AC-4 (17)']
end
