control 'SV-96531' do
  title 'Apple iOS must implement the management setting: require the user to enter a password when connecting to an AirPlay-enabled device for the first time.'
  desc 'When a user is allowed to use AirPlay without a password, there is the potential that it may mistakenly associate the Apple iOS device with an AirPlay-enabled device other than the one intended (i.e., by choosing the wrong one from the AirPlay list displayed). This creates the potential that someone in control of a mistakenly associated device may obtain DoD-sensitive information without authorization. Requiring a password before such an association mitigates this risk. Passwords do not require any administration, nor must they comply with any complexity requirements.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review configuration settings to confirm "Require passcode on first AirPlay pairing" is enabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Require passcode on first AirPlay pairing" is checked.

Alternatively, verify the text "<key>forceAirPlayOutgoingRequestsPairingPassword</key><false/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "AirPlay outgoing requests pairing password enforced" is listed.

If "Require passcode on first AirPlay pairing" is unchecked in the Apple iOS management tool, "<key>forceAirPlayOutgoingRequestsPairingPassword</key><true/>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "AirPlay outgoing requests pairing password enforced", this is a finding.'
  desc 'fix', 'Install a configuration profile to require the user to enter a password when connecting to an AirPlay-enabled device for the first time.'
  impact 0.3
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-81609r1_chk'
  tag severity: 'low'
  tag gid: 'V-81817'
  tag rid: 'SV-96531r1_rule'
  tag stig_id: 'AIOS-12-011100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-88667r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000063']
  tag nist: ['AC-17 a']
end
