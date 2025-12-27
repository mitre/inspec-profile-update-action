control 'SV-91279' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Disable S Voice.'
  desc "On Samsung Android 7 with Knox devices, users may be able to access the device's contact database or calendar to obtain phone numbers and other information using a human voice even when the mobile device is locked. Often this information is personally identifiable information (PII), which is considered sensitive. It could also be used by an adversary to profile the user or engage in social engineering to obtain further information from other unsuspecting users. Disabling access to the contact database and calendar in these situations mitigates the risk of this attack. The Authorizing Official (AO) may waive this requirement with written notice if the operational environment requires this capability.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Note, this requirement is Not Applicable if the AO has approved unmanaged personal space/container (COPE use case). The site must have an AO signed document showing the AO has assumed the risk for using an unmanaged personal container.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is configured to disable S Voice. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow S Voice" checkbox in the "Android Restrictions" rule. 
2. Verify the checkbox is not selected.

On the Samsung Android 7 with Knox device, do the following:
1. Open the device settings.
2. Select "Applications".
3. Verify the S Voice application cannot be selected.

If the MDM console "Allow S Voice" checkbox is selected or on the Samsung Android 7 with Knox device, the S Voice application can be launched, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable S Voice.

On the MDM console, deselect the "Allow S Voice" checkbox in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76251r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76583'
  tag rid: 'SV-91279r1_rule'
  tag stig_id: 'KNOX-07-012700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83277r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
