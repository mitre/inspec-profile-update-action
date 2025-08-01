control 'SV-237263' do
  title 'Apple iOS must implement the management setting: Disable Allow Shared Albums.'
  desc 'Storing data with a non-DoD cloud provider may leave the data vulnerable to breach. Disabling non-DoD cloud services mitigates this risk.

Note: If the AO has approved the use/storage of DoD data in one or more personal (unmanaged) apps, allowing unrestricted activity by the user in downloading and installing personal (unmanaged) apps on the iOS 11 device may not be warranted due to the risk of possible loss of or unauthorized access to DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Note: This requirement is Not Applicable if the AO has approved users' full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts (see Section 2.9 of the STIG Supplemental document for more details). The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store. 

Review configuration settings to confirm "Allow Shared Albums" is disabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Allow Shared Albums" is not checked.

On the Apple iOS device:
1. Open the "Settings" app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "iCloud Photos not allowed" is listed.

If "Allow Shared Albums" is not disabled in the Apple iOS management tool or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "iCloud Photos not allowed", this is a finding.)
  desc 'fix', 'Configure the Apple iOS configuration profile to disable "Allow Shared Albums".'
  impact 0.5
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-40482r642339_chk'
  tag severity: 'medium'
  tag gid: 'V-237263'
  tag rid: 'SV-237263r642341_rule'
  tag stig_id: 'AIOS-12-011300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-40445r642340_fix'
  tag 'documentable'
  tag legacy: ['SV-96535', 'V-81821']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
