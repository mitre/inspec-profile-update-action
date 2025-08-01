control 'SV-219359' do
  title 'Apple iOS/iPadOS must not allow backup to remote systems (iCloud document and data synchronization).'
  desc "Backups to remote systems (including cloud backup and cloud document syncing) can leave data vulnerable to breach on the external systems, which often offer less protection than the MOS. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD-sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

Note: If the AO has approved the use/storage of DoD data in one or more personal (unmanaged) apps, allowing unrestricted activity by the user in downloading and installing personal (unmanaged) apps on the iOS 11 device may not be warranted due to the risk of possible loss of or unauthorized access to DoD data.

SFR ID: FMT_MOF_EXT.1.2 #40"
  desc 'check', %q(Note: This requirement is Not Applicable if the AO has approved users' full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts (see Section 2.9 of the STIG Supplemental document for more details). The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store. 

Review configuration settings to confirm "Allow iCloud documents & data" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the Apple iOS/iPadOS management tool, verify "Allow iCloud documents & data" is unchecked.

Alternatively, verify the text "<key>allowCloudDocumentSync</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the policy.
5. Tap "Restrictions".
6. Verify "Documents in the Cloud not allowed".

Note: This also verifies that iCloud Drive and iCloud Photo Library is disabled.

If "Allow iCloud documents & data" is checked in the Apple iOS/iPadOS management tool, "<key>allowCloudDocumentSync</key> <true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Documents in the Cloud not allowed", this is a finding.)
  desc 'fix', 'Install a configuration profile to disable iCloud documents and data.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21084r547592_chk'
  tag severity: 'medium'
  tag gid: 'V-219359'
  tag rid: 'SV-219359r604137_rule'
  tag stig_id: 'AIOS-13-004200'
  tag gtitle: 'PP-MDF-302220'
  tag fix_id: 'F-21083r547593_fix'
  tag 'documentable'
  tag legacy: ['SV-106549', 'V-97445']
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
