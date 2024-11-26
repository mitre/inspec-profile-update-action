control 'SV-93125' do
  title 'Apple iOS must implement the management setting: Disable Allow iCloud Photo Library.'
  desc 'Storing data with a non-DoD cloud provider may leave the data vulnerable to breach. Disabling non-DoD cloud services mitigates this risk.

Note: If the AO has approved the use/storage of DoD data in one or more personal (unmanaged) apps, allowing unrestricted activity by the user in downloading and installing personal (unmanaged) apps on the iOS 11 device may not be warranted due to the risk of possible loss of or unauthorized access to DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Note: This requirement is Not Applicable if the AO has approved users' full access to the Apple App Store for downloading unmanaged (personal) apps and syncing personal data on the device with personal cloud data storage accounts (see Section 2.9 of the STIG Supplemental document for more details). The site must have an AO-signed document showing the AO has assumed the risk for users' full access to the Apple App Store. 

Review configuration settings to confirm "Allow iCloud Photo Library" is disabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Allow iCloud Photo Library" is not checked.

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "iCloud Photo Library not allowed" is listed.

If "Allow iCloud Photo Library" is not disabled in the Apple iOS management tool or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "iCloud Photo Library not allowed", this is a finding.)
  desc 'fix', 'Configure the Apple iOS configuration profile to disable "Allow iCloud Photo Library".'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78419'
  tag rid: 'SV-93125r1_rule'
  tag stig_id: 'AIOS-11-011700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-85151r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
