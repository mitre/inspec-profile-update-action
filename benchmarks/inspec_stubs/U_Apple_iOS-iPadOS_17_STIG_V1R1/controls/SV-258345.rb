control 'SV-258345' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: require passcode for incoming Airplay connection requests.'
  desc 'When an incoming AirPlay request is allowed without a password, it may mistakenly associate the iPhone and iPad with an AirPlay-enabled device other than the one intended (i.e., by choosing the wrong one from the AirPlay list displayed). This creates the potential for someone in control of a mistakenly associated device to obtain DOD sensitive information without authorization. Requiring a password before such an association mitigates this risk. Passwords do not require any administration and are not required to comply with any complexity requirements.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review configuration settings to confirm "Require passcode for incoming AirPlay connection requests" is enabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Require passcode for incoming AirPlay connection requests" is checked.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "AirPlay incoming requests pairing password enforced" is listed.

If "Require passcode for incoming AirPlay connection requests" is unchecked in the Apple iOS/iPadOS management tool or the restrictions policy on the iPhone and iPad does not list "AirPlay incoming requests pairing password enforced", this is a finding.'
  desc 'fix', 'Install a configuration profile to require that incoming AirPlay connection requests enter a password when connecting to a DOD iOS/iPadOS device.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62086r927716_chk'
  tag severity: 'low'
  tag gid: 'V-258345'
  tag rid: 'SV-258345r927718_rule'
  tag stig_id: 'AIOS-17-010950'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62010r927717_fix'
  tag 'documentable'
  tag cci: ['CCI-000063']
  tag nist: ['AC-17 a']
end
