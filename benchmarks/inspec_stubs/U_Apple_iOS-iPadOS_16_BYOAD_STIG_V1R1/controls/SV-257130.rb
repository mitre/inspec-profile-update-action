control 'SV-257130' do
  title 'Apple iOS/iPadOS 16 must not allow managed apps to write contacts to unmanaged contacts accounts.'
  desc 'Managed apps have been approved for the handling of DOD sensitive information. Unmanaged apps are provided for productivity and morale purposes but are not approved to handle DOD sensitive information. Examples of unmanaged apps include those for news services, travel guides, maps, and social networking. 

If a document were to be viewed in a managed app and the user had the ability to open this same document in an unmanaged app, this could lead to the compromise of sensitive DOD data. In some cases, the unmanaged apps are connected to cloud backup or social networks that would permit dissemination of DOD sensitive information to unauthorized individuals. Not allowing data to be opened within unmanaged apps mitigates the risk of compromising sensitive data.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review configuration settings to confirm "Allow managed apps to write contacts to unmanaged contacts accounts" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the Apple iOS/iPadOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS/iPadOS management tool, verify "Allow managed apps to write contacts to unmanaged contacts accounts" is unchecked.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management". 
4. Tap the Configuration Profile from the iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Allow managed apps to write contacts to unmanaged contacts accounts" is not listed.

If "Allow managed apps to write contacts to unmanaged contacts accounts" is checked in the iOS/iPadOS management tool or the restrictions policy on the iPhone and iPad lists "Allow managed apps to write contacts to unmanaged contacts accounts", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent managed apps from writing contacts to unmanaged contacts accounts.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60815r904288_chk'
  tag severity: 'low'
  tag gid: 'V-257130'
  tag rid: 'SV-257130r904290_rule'
  tag stig_id: 'AIOS-16-712300'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-60756r904289_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
