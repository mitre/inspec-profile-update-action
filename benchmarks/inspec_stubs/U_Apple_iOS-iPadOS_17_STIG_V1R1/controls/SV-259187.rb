control 'SV-259187' do
  title 'Apple iOS/iPadOS 17 must not allow backup to remote systems (iCloud document and data synchronization).'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DOD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DOD sensitive information.

SFR ID: FMT_MOF_EXT.1.2 #40'
  desc 'check', %q(Note: This requirement is not applicable if the authorizing official (AO) has approved users' full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts. The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store. 

Review configuration settings to confirm "Allow iCloud documents & data" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

This requirement will become "Supervised only" in a future iOS/iPadOS release.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the Apple iOS/iPadOS management tool, verify "Allow iCloud documents & data" is unchecked.

Alternatively, verify the text "<key>allowCloudDocumentSync</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the policy.
5. Tap "Restrictions".
6. Verify "Documents in the Cloud not allowed" is listed.

Note: This also verifies that iCloud Drive and iCloud Photo Library are disabled.

If "Allow iCloud documents & data" is checked in the Apple iOS/iPadOS management tool, "<key>allowCloudDocumentSync</key> <true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Documents in the Cloud not allowed", this is a finding.)
  desc 'fix', 'Install a configuration profile to disable iCloud documents and data.

This requirement will become "Supervised only" in a future iOS/iPadOS release.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62927r935529_chk'
  tag severity: 'medium'
  tag gid: 'V-259187'
  tag rid: 'SV-259187r935531_rule'
  tag stig_id: 'AIOS-17-003200'
  tag gtitle: 'PP-MDF-333250'
  tag fix_id: 'F-62836r935530_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
