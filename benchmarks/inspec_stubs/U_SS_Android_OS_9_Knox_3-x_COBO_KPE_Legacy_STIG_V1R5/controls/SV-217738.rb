control 'SV-217738' do
  title 'Samsung Android must be configured to enforce that Secure Startup is enabled. This requirement is Not Applicable (NA) to Galaxy S10 (or newer) devices.'
  desc 'Secure Startup protects the Samsung Android device by requiring the user password to be entered before the device starts up. When Secure Startup is enabled, the default cryptographic keys are replaced with keys derived from the user password. 

This feature must be enabled for a Samsung Android device to be in the NIAP-certified Common Criteria (CC) mode of operation.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that Secure Startup is enabled. 

This procedure is performed on the Samsung Android device prior to Galaxy S10 only. 

This setting cannot be managed by the MDM administrator and is a User-Based Enforcement (UBE) requirement. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Biometric and security". 
3. Tap "Other security settings". 
4. Tap "Secure startup". 
5. Verify that "Require password when device powers on" is already selected and "Do not require" is not selected. 

If on the Samsung Android device "Do not require" is selected, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable Secure Startup. 

This guidance is only applicable to devices prior to Galaxy S10. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Biometrics and security". 
3. Tap "Other security settings". 
4. Tap "Secure startup". 
5. Tap option "Require password when device powers on". 
6. Tap "Apply". 
7. Enter the current password.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE Legacy'
  tag check_id: 'C-18956r362362_chk'
  tag severity: 'medium'
  tag gid: 'V-217738'
  tag rid: 'SV-217738r388482_rule'
  tag stig_id: 'KNOX-09-001425'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18954r362363_fix'
  tag 'documentable'
  tag legacy: ['SV-103723', 'V-93637']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
