control 'SV-219361' do
  title 'Apple iOS/iPadOS must not allow backup to remote systems (My Photo Stream).'
  desc "When My Photo Stream is enabled, sensitive photos will be uploaded automatically to Apple-specified servers and available on other iPhone and iPads associated with the same Apple ID, provided that the other device also has My Photo Stream enabled. This potentially places sensitive photos on a server outside of DoD's control, potentially granting availability to non-DoD devices. Disabling My Photo Stream mitigates this risk.

Note: If the AO has approved the use/storage of DoD data in one or more personal (unmanaged) apps, allowing unrestricted activity by the user in downloading and installing personal (unmanaged) apps on the iOS 11 device may not be warranted due to the risk of possible loss of or unauthorized access to DoD data.

SFR ID: FMT_MOF_EXT.1.2 #40"
  desc 'check', %q(Note: This requirement is Not Applicable if the AO has approved users' full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts (see Section 2.9 of the STIG Supplemental document for more details). The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store. 

Review configuration settings to confirm "Allow My Photo Stream" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow My Photo Stream" is unchecked.

Alternatively, verify the text "<key>allowPhotoStream</key><false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Photo Stream not allowed" is listed.

If "Allow Photo Stream" is checked in the Apple iOS/iPadOS management tool, "<key>allowPhotoStream</key> <true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Photo Stream not allowed", this is a finding.)
  desc 'fix', 'Install a configuration profile to disable My Photo Stream.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21086r547598_chk'
  tag severity: 'medium'
  tag gid: 'V-219361'
  tag rid: 'SV-219361r604137_rule'
  tag stig_id: 'AIOS-13-004400'
  tag gtitle: 'PP-MDF-302220'
  tag fix_id: 'F-21085r547599_fix'
  tag 'documentable'
  tag legacy: ['SV-106553', 'V-97449']
  tag cci: ['CCI-000366', 'CCI-001761']
  tag nist: ['CM-6 b', 'CM-7 (1) (b)']
end
