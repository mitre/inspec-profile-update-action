control 'SV-103981' do
  title 'Samsung Android must be configured to enable Knox Common Criteria (CC) Mode.'
  desc '<0> [object Object]'
  desc 'check', 'Review device configuration settings to confirm that Knox CC Mode is enabled. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox restrictions" group, verify that "enable CC mode" is selected. 

On the Samsung Android device, to verify that CC Mode has not failed, do the following: 
1. Open Settings. 
2. Tap "About phone". 
3. Tap "Software information". 
4. Verify that the Security software version for MDF does not display "Disabled". 

For Samsung Android devices prior to Galaxy S10, to verify that CC Mode is enabled, do the following: 
1. Open Settings. 
2. Tap "Biometric and security". 
3. Tap "Secure startup". 
4. Verify that "Do not require" is disabled. 

For Galaxy S10 (or newer devices), to verify that CC Mode is enabled, do the following: 
1. Open Settings. 
2. Tap "Biometric and security". 
3. Verify that "Strong Protection" is enabled and cannot be disabled. 

If on the MDM console "enable CC mode" is not selected, or on the Samsung Android device the software version for "MDF" displays "Disabled", or on a Galaxy S10 (or newer device) "Strong Protection" can be disabled, or on a device older than a Galaxy S10 "Do not require" is not disabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable Knox CC Mode. 

On the MDM console, for the device, in the "Knox restrictions" group, select "enable CC mode". 

The following configuration must also be implemented for the Samsung Android device to be operating in the NIAP-certified compliant CC Mode of operation: 
- KNOX-09-001445/(KNOX-09-001475): Minimum password quality 
- KNOX-09-000505: Disable face 
- KNOX-09-000435/(KNOX-09-000445): Max password failures for local wipe 
- KNOX-09-001375/(KNOX-09-001365): Password recovery 
- KNOX-09-001395/(KNOX-09-001405): Password history length 
- KNOX-09-001055/(KNOX-09-001045): Revocation check 
- KNOX-09-001345/(KNOX-09-001335): OCSP check 
- KNOX-09-001425: Secure Startup (for devices prior to Galaxy S10)
- KNOX-09-001485: Strong Protection (for Galaxy S10 (or newer) devices)
- KNOX-09-000985: Enable external storage encryption

Note: STIGIDs listed above not in parentheses are personal space requirements. STIGIDs in parentheses are workspace requirements.'
  impact 0.7
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(Legacy)'
  tag check_id: 'C-93213r1_chk'
  tag severity: 'high'
  tag gid: 'V-93895'
  tag rid: 'SV-103981r1_rule'
  tag stig_id: 'KNOX-09-000715'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-100143r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
