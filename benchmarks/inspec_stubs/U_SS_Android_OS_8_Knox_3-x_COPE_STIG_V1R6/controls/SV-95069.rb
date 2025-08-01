control 'SV-95069' do
  title 'The Samsung Android 8 with Knox CONTAINER must implement the management setting: Disable S Voice.'
  desc "On Samsung Android 8 with Knox device CONTAINERs, users may be able to access the device's contact database or calendar to obtain phone numbers and other information using a human voice even when the mobile device is locked. Often this information is personally identifiable information (PII), which is considered sensitive. It could also be used by an adversary to profile the user or engage in social engineering to obtain further information from other unsuspecting users. Disabling access to the contact database and calendar in these situations mitigates the risk of this attack. The Authorizing Official (AO) may waive this requirement with written notice if the operational environment requires this capability.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Samsung Android 8 with Knox CONTAINER configuration settings to determine if the mobile device is configured to disable S Voice. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device CONTAINER.

On the MDM CONTAINER console, do the following:
1. Ask the MDM Administrator to display the "Allow S Voice" check box in the "Android Restrictions" rule. 
2. Verify the check box is not selected.

On the Samsung Android 8 with Knox device CONTAINER, do the following:
1. Open the device settings.
2. Select "Applications".
3. Verify the S Voice application cannot be selected.

If the MDM console "Allow S Voice" check box is selected or on the Samsung Android 8 with Knox device CONTAINER, the S Voice application can be launched, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox CONTAINER to disable S Voice.

On the MDM CONTAINER console, deselect the "Allow S Voice" check box in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80037r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80365'
  tag rid: 'SV-95069r1_rule'
  tag stig_id: 'KNOX-08-014800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87171r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
