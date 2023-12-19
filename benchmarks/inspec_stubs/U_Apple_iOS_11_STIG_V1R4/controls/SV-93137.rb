control 'SV-93137' do
  title 'Apple iOS must implement the management setting: not share location data through iCloud.'
  desc "Sharing of location data is an operations security (OPSEC) risk because it potentially allows an adversary to determine a DoD user's location and movements and patterns in those movements over time. An adversary could use this information to target the user or to gather intelligence on the user's likely activities. Using commercial cloud services to store and handle location data could leave the data vulnerable to breach, particularly by sophisticated adversaries. Disabling the use of such services mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm "Share My Location" is disabled. Note that this is a User based Enforcement (UBE) control, which cannot be managed by an MDM server.

This check procedure is performed on the Apple iOS device only.

On the Apple iOS device:
1. Open the Settings app.
2. Tap "Privacy".
3. Tap "Location Services".
4. Tap "Share My Location".
5. Verify "Share My Location" is off.

If "Share My Location" is toggled to the right and appears green on the Apple iOS device, this is a finding.'
  desc 'fix', 'The user must configure Apple iOS to disable location sharing through iCloud.'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78431'
  tag rid: 'SV-93137r1_rule'
  tag stig_id: 'AIOS-11-012300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-85163r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
