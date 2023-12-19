control 'SV-93095' do
  title 'Apple iOS must not allow backup to remote systems (iCloud Keychain).'
  desc "The iCloud Keychain is an Apple iOS function that will store users' account names and passwords in iCloud and then synchronize this data among the users' Macs, iPhones, and iPads. An adversary may use any of the stored iCloud keychain passwords after unlocking one of the synchronized devices. If a user is synchronizing devices, the user must protect all of the devices to prevent unauthorized use of the passcodes. Moreover, the keychain being transmitted through the cloud opens the possibility that a well-resourced, sophisticated adversary could compromise the cloud-transmitted keychain. Not allowing the iCloud Keychain feature mitigates the risk of the encrypted set of passwords being compromised when transmitted through the cloud or synchronized across multiple devices.

Note: If the AO has approved the use/storage of DoD data in one or more personal (unmanaged) apps, allowing unrestricted activity by the user in downloading and installing personal (unmanaged) apps on the iOS 11 device may not be warranted due to the risk of possible loss of or unauthorized access to DoD data.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', %q(Note: This requirement is Not Applicable if the AO has approved users' full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts (see Section 2.9 of the STIG Supplemental document for more details). The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store. 

Review configuration settings to confirm iCloud keychain is disabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the Apple iOS management tool, verify "Allow iCloud keychain" is unchecked.

Alternatively, verify the text "<key>allowCloudKeychainSync</key><false/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Verify "iCloud Keychain not allowed" is listed.

If "Allow iCloud keychain" is checked in the Apple iOS management tool, "<key>allowCloudKeychainSync</key><true/>" appears in the configuration profile, or "iCloud Keychain not allowed" is not listed on the Apple iOS device, this is a finding.)
  desc 'fix', 'Install a configuration profile to disable iCloud keychain.'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78389'
  tag rid: 'SV-93095r1_rule'
  tag stig_id: 'AIOS-11-004300'
  tag gtitle: 'PP-MDF-302220'
  tag fix_id: 'F-85121r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
