control 'SV-35945' do
  title 'Unauthorized accounts must not have the Impersonate a client after authentication user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Impersonate a client after authentication" user right allows a program to impersonate another user or account to run on their behalf.  An attacker could potentially use this to elevate privileges.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Impersonate a client after authentication" right, this is a finding:

Administrators
Service
Local Service
Network Service'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Impersonate a client after authentication" to only include the following accounts or groups:

Administrators
Service
Local Service
Network Service'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60867r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26490'
  tag rid: 'SV-35945r2_rule'
  tag stig_id: 'WINUR-000025'
  tag gtitle: 'Impersonate a client after authentication'
  tag fix_id: 'F-65599r2_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
