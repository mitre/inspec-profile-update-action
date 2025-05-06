control 'SV-228745' do
  title 'Apple iOS/iPadOS must not allow backup to remote systems (iCloud Photo Sharing, also known as Shared Photo Streams).'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD-sensitive Information.

SFR ID: FMT_MOF_EXT.1.2 #40'
  desc 'check', %q(Note: This requirement is Not Applicable if the AO has approved users full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts (see Section 2.9 of the STIG Supplemental document for more details). The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store. 

Review configuration settings to confirm "Allow iCloud Photos" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow iCloud Photos" is unchecked.

Alternatively, verify the text "<key>allowSharedStream</key><false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Shared streams not allowed" is listed.

If "Allow iCloud Photos" is checked in the Apple iOS/iPadOS management tool, "<key>allowSharedStream</key><true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Shared streams not allowed", this is a finding.)
  desc 'fix', 'Install a configuration profile to disable "Allow iCloud Photos".'
  impact 0.5
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-30980r509863_chk'
  tag severity: 'medium'
  tag gid: 'V-228745'
  tag rid: 'SV-228745r561031_rule'
  tag stig_id: 'AIOS-14-004100'
  tag gtitle: 'PP-MDF-302220'
  tag fix_id: 'F-30957r509864_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000097', 'CCI-000370']
  tag nist: ['CM-6 b', 'AC-20 (2)', 'CM-6 (1)']
end
