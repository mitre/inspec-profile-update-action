control 'SV-250954' do
  title 'Apple iOS/iPadOS 15 must implement the management setting: Disable Allow Shared Albums.'
  desc 'Storing data with a non-DoD cloud provider may leave the data vulnerable to breach. Disabling non-DoD cloud services mitigates this risk.

Note: If the Authorizing Official (AO) has approved the use/storage of DoD data in one or more personal (unmanaged) apps, allowing unrestricted activity by the user in downloading and installing personal (unmanaged) apps on the iOS 14 device may not be warranted due to the risk of possible loss of or unauthorized access to DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Note: This requirement is not applicable if the AO has approved users' full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts. The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store. 

Review configuration settings to confirm "Allow Shared Albums" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow Shared Albums" is not checked.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "iCloud Photos not allowed" is listed.

If "Allow Shared Albums" is not disabled in the Apple iOS/iPadOS management tool or the restrictions policy on the iPhone and iPad does not list "iCloud Photos not allowed", this is a finding.)
  desc 'fix', 'Configure the Apple iOS/iPadOS configuration profile to disable "Allow Shared Albums".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54389r801951_chk'
  tag severity: 'medium'
  tag gid: 'V-250954'
  tag rid: 'SV-250954r801953_rule'
  tag stig_id: 'AIOS-15-011100'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54343r801952_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
