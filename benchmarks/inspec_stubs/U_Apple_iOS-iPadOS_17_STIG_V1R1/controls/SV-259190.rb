control 'SV-259190' do
  title 'Apple iOS/iPadOS 17 must not allow backup to remote systems (iCloud Photo Sharing, also known as Shared Stream or Shared Photo Stream).'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DOD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DOD sensitive information.

SFR ID: FMT_MOF_EXT.1.2 #40'
  desc 'check', %q(Note: This requirement is not applicable if the authorizing official (AO) has approved users' full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts. The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store. 

Review configuration settings to confirm "Allow Shared Stream" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow Shared Stream" is unchecked.

Alternatively, verify the text "<key>allowSharedStream</key><false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Shared Streams not allowed" is listed.

If "AllowShared Photo Stream" is checked in the Apple iOS/iPadOS management tool, "<key>allowSharedStream</key><true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Shared Streams not allowed", this is a finding.

This requirement will become "Supervised only" in a future iOS/iPadOS release.)
  desc 'fix', 'Install a configuration profile to disable "Allow Shared PhotoStream".

This requirement will become "Supervised only" in a future iOS/iPadOS release.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62930r935538_chk'
  tag severity: 'medium'
  tag gid: 'V-259190'
  tag rid: 'SV-259190r935540_rule'
  tag stig_id: 'AIOS-17-003500'
  tag gtitle: 'PP-MDF-333250'
  tag fix_id: 'F-62839r935539_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
