control 'SV-228763' do
  title 'Apple iOS/iPadOS must implement the management setting: not share location data through iCloud.'
  desc "Sharing of location data is an operations security (OPSEC) risk because it potentially allows an adversary to determine a DoD user's location, movements, and patterns in those movements over time. An adversary could use this information to target the user or to gather intelligence on the user's likely activities. Using commercial cloud services to store and handle location data could leave the data vulnerable to breach, particularly by sophisticated adversaries. Disabling the use of such services mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm "Share My Location" is disabled. Note that this is a User Based Enforcement (UBE) control, which cannot be managed by an MDM server.

This check procedure is performed on the iPhone and iPad only.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "Privacy".
3. Tap "Location Services".
4. If the AO has not approved use of personal iCloud accounts on the device, verify "Share My Location" is grayed-out (cannot be selected).
5. If the AO has approved the use of personal iCloud accounts on the device, tap "Share My Location".
6. Verify "Share My Location" is off.

If "Share My Location" is not grayed-out (cannot be selected) when the AO has not approved use of personal iCloud accounts on the device, this is a finding.

If "Share My Location" is toggled to the right and appears green on the iPhone and iPad when the AO has approved the use of personal iCloud accounts, this is a finding.'
  desc 'fix', 'The user must configure Apple iOS/iPadOS to disable location sharing through iCloud.'
  impact 0.5
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-30998r569179_chk'
  tag severity: 'medium'
  tag gid: 'V-228763'
  tag rid: 'SV-228763r561046_rule'
  tag stig_id: 'AIOS-14-010100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30975r509918_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
