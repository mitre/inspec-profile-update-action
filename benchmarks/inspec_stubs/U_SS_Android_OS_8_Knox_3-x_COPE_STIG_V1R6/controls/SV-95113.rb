control 'SV-95113' do
  title 'Samsung Android 8 with Knox must implement the management setting: Disable sharing of clipboard information outside the CONTAINER.'
  desc 'The CONTAINER clipboard can include potentially DoD sensitive data such as names, contacts, dates and times, and locations. If made available outside the CONTAINER, this information will be accessible to personal applications, resulting in potential compromise of DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing disabled sharing of clipboard data outside the CONTAINER.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow clipboard data outside CONTAINER" setting in the "Android Knox CONTAINER >> CONTAINER Restrictions" rule. 
2. Verify the setting is disabled.

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Copy text to the clipboard using any CONTAINER application.
3. Verify this text cannot be pasted to an application in the personal space.

If the MDM console "Allow clipboard data outside CONTAINER" is not set to "Disabled" or on the Samsung Android 8 with Knox device, the user is able to paste work data, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce disabled sharing of clipboard data outside the CONTAINER.

On the MDM console, disable the "Allow clipboard data outside CONTAINER" setting in the "Android Knox CONTAINER >> CONTAINER Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80409'
  tag rid: 'SV-95113r1_rule'
  tag stig_id: 'KNOX-08-022200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87215r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
