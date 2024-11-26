control 'SV-253498' do
  title 'The "Impersonate a client after authentication" user right must only be assigned to Administrators, Service, Local Service, and Network Service.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Impersonate a client after authentication" user right allows a program to impersonate another user or account to run on their behalf. An attacker could potentially use this to elevate privileges.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Impersonate a client after authentication" user right, this is a finding:

Administrators
LOCAL SERVICE
NETWORK SERVICE
SERVICE'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Impersonate a client after authentication" to only include the following groups or accounts:

Administrators
LOCAL SERVICE
NETWORK SERVICE
SERVICE'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56951r829576_chk'
  tag severity: 'medium'
  tag gid: 'V-253498'
  tag rid: 'SV-253498r829578_rule'
  tag stig_id: 'WN11-UR-000110'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56901r829577_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
