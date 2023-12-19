control 'SV-258344' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: require the user to enter a password when connecting to an AirPlay-enabled device.'
  desc 'When a user is allowed to use AirPlay without a password, it may mistakenly associate the iPhone and iPad with an AirPlay-enabled device other than the one intended (i.e., by choosing the wrong one from the AirPlay list displayed). This creates the potential for someone in control of a mistakenly associated device to obtain DOD sensitive information without authorization. Requiring a password before such an association mitigates this risk. Passwords do not require any administration and are not required to comply with any complexity requirements.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review configuration settings to confirm "Require passcode on outgoing AirPlay request" is enabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Require passcode on outgoing AirPlay request" is checked.

Alternatively, verify the text "<key>forceAirPlayOutgoingRequestsPairingPassword</key><false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "AirPlay outgoing requests pairing password enforced" is listed.

If "Require passcode on outgoing AirPlay request" is unchecked in the Apple iOS/iPadOS management tool, "<key>forceAirPlayOutgoingRequestsPairingPassword</key><true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "AirPlay outgoing requests pairing password enforced", this is a finding.'
  desc 'fix', 'Install a configuration profile to require the user to enter a password when connecting to an AirPlay-enabled device.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62085r927713_chk'
  tag severity: 'low'
  tag gid: 'V-258344'
  tag rid: 'SV-258344r927715_rule'
  tag stig_id: 'AIOS-17-010900'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62009r927714_fix'
  tag 'documentable'
  tag cci: ['CCI-000063']
  tag nist: ['AC-17 a']
end
