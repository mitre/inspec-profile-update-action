control 'SV-91309' do
  title 'The Samsung Android 7 with Knox must be configured to Disable Bixby.'
  desc "On MOS devices, unauthorized users (may be able to) access the device's contact database or calendar to obtain phone numbers and other information using a human voice even when the mobile device is locked. Often this information is personally identifiable information (PII), which is considered sensitive. It could also be used by an adversary to profile the user or engage in social engineering to obtain further information from other unsuspecting users.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Not Applicable if the AO has approved unmanaged personal space/container (COPE use case). The site must have an AO signed document showing the AO has assumed the risk for using an unmanaged personal container.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is configured to disable Bixby.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Application disable list" setting in the "Android Application" rule. 
2. Verify the list contains all Bixby related packages.

On the Samsung Android 7 with Knox device, do the following:
1. Press the Bixby hardware button.
2. Verify Bixby does not start.

If the Samsung Android 7 with Knox device starts Bixby when pressing the hardware Bixby button, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable Bixby.

On the MDM console, add all packages associated with the Bixby feature to the "Application disable list" setting in the "Android Applications" rule. 

Note: Refer to the Supplemental document for additional information.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76283r1_chk'
  tag severity: 'low'
  tag gid: 'V-76613'
  tag rid: 'SV-91309r1_rule'
  tag stig_id: 'KNOX-07-017800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83307r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
