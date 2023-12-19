control 'SV-217679' do
  title 'Samsung Android must be configured to enable Knox Common Criteria (CC) Mode.'
  desc '<0> [object Object]'
  desc 'check', 'Review device configuration settings to confirm that Knox CC Mode is enabled. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox restrictions" group, verify that "enable CC mode" is selected. 

On the Samsung Android device, to verify that CC mode has not failed, do the following: 
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

The following configuration must also be implemented for the Samsung Android device to be operating in the NIAP-certified compliant CC mode of operation: 
- KNOX-09-001440: Minimum password quality 
- KNOX-09-000500: Disable face 
- KNOX-09-000430/(KNOX-09-000440): Max password failures for local wipe 
- KNOX-09-001370/(KNOX-09-001360): Password recovery 
- KNOX-09-001390/(KNOX-09-001400): Password history length 
- KNOX-09-001050/(KNOX-09-001040): Revocation check 
- KNOX-09-001340/(KNOX-09-001330): OCSP check 
- KNOX-09-001420: Secure Startup (for devices prior to Galaxy S10)
- KNOX-09-001480: Strong Protection (for Galaxy S10 (or newer) devices)
- KNOX-09-000980: Enable external storage encryption or disallow mount physical media

Note: STIGIDs listed above not in parentheses are personal space requirements. STIGIDs in parentheses are workspace requirements.'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18898r362066_chk'
  tag severity: 'high'
  tag gid: 'V-217679'
  tag rid: 'SV-217679r388482_rule'
  tag stig_id: 'KNOX-09-000710'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18896r362067_fix'
  tag legacy: ['SV-102983', 'V-92895']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
