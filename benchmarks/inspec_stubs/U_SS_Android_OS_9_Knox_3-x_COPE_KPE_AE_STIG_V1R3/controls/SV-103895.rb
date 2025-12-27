control 'SV-103895' do
  title 'Samsung Android must be configured to disable developer modes.'
  desc 'Developer modes expose features of the mobile operating system that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review device configuration settings to confirm that debugging features are disallowed. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Android user restrictions" group, verify that "disallow debugging features" is selected. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "About phone". 
3. Tap "Software information". 
4. Tap "Build number". 
5. Verify that the message "Unable to perform action" is displayed. 

If on the MDM console "disallow debugging features" is not selected, or on the Samsung Android device the "Unable to perform action" message is not displayed, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disallow debugging features. 

On the MDM console, for the device, in the "Android user restrictions" group, select "disallow debugging features".'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(AE)'
  tag check_id: 'C-93127r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93809'
  tag rid: 'SV-103895r1_rule'
  tag stig_id: 'KNOX-09-000920'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-100055r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
