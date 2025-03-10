control 'SV-219360' do
  title 'Apple iOS/iPadOS must not allow backup to remote systems (iCloud Keychain).'
  desc "The iCloud Keychain is an Apple iOS/iPadOS function that will store users' account names and passwords in iCloud and then synchronize this data among the users' Macs, iPhones, and iPads. An adversary may use any of the stored iCloud keychain passwords after unlocking one of the synchronized devices. If a user is synchronizing devices, the user must protect all of the devices to prevent unauthorized use of the passcodes. Moreover, the keychain being transmitted through the cloud opens the possibility that a well-resourced, sophisticated adversary could compromise the cloud-transmitted keychain. Not allowing the iCloud Keychain feature mitigates the risk of the encrypted set of passwords being compromised when transmitted through the cloud or synchronized across multiple devices.

Note: If the AO has approved the use/storage of DoD data in one or more personal (unmanaged) apps, allowing unrestricted activity by the user in downloading and installing personal (unmanaged) apps on the iOS 11 device may not be warranted due to the risk of possible loss of or unauthorized access to DoD data.

SFR ID: FMT_MOF_EXT.1.2 #40"
  desc 'check', %q(Note: This requirement is Not Applicable if the AO has approved users' full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts (see Section 2.9 of the STIG Supplemental document for more details). The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store. 

Review configuration settings to confirm iCloud keychain is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the Apple iOS/iPadOS management tool, verify "Allow iCloud keychain" is unchecked.

Alternatively, verify the text "<key>allowCloudKeychainSync</key><false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Verify "iCloud Keychain not allowed" is listed.

If "Allow iCloud keychain" is checked in the Apple iOS/iPadOS management tool, "<key>allowCloudKeychainSync</key><true/>" appears in the configuration profile, or "iCloud Keychain not allowed" is not listed on the iPhone and iPad, this is a finding.)
  desc 'fix', 'Install a configuration profile to disable iCloud keychain.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21085r547595_chk'
  tag severity: 'medium'
  tag gid: 'V-219360'
  tag rid: 'SV-219360r604137_rule'
  tag stig_id: 'AIOS-13-004300'
  tag gtitle: 'PP-MDF-302220'
  tag fix_id: 'F-21084r547596_fix'
  tag 'documentable'
  tag legacy: ['SV-106551', 'V-97447']
  tag cci: ['CCI-000366', 'CCI-001772', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-7 (5) (a)', 'CM-6 (1)']
end
