control 'SV-93091' do
  title 'Apple iOS 
must not allow backup to remote systems (iCloud).'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the MOS. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD-sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

Note: If the AO has approved the use/storage of DoD data in one or more personal (unmanaged) apps, allowing unrestricted activity by the user in downloading and installing personal (unmanaged) apps on the iOS 11 device may not be warranted due to the risk of possible loss of or unauthorized access to DoD data.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', %q(Note: This requirement is Not Applicable if the AO has approved users' full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts (see Section 2.9 of the STIG Supplemental document for more details). The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store.

Review configuration settings to confirm iCloud Backup is disabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Allow iCloud backup" is unchecked.

Alternatively, verify the text "<key>allowCloudBackup</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the policy.
5. Verify "iCloud backup not allowed".

If "Allow iCloud backup" is checked in the Apple iOS management tool, "<key>allowCloudBackup</key><true/>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "iCloud backup not allowed", this is a finding.)
  desc 'fix', 'Install a configuration profile to disable iCloud Backup.'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77947r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78385'
  tag rid: 'SV-93091r1_rule'
  tag stig_id: 'AIOS-11-004100'
  tag gtitle: 'PP-MDF-302220'
  tag fix_id: 'F-85117r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
