control 'SV-103703' do
  title 'Samsung Android must be configured to disable developer modes.'
  desc 'Developer modes expose features of the mobile operating system that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review device configuration settings to confirm developer mode is disallowed. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox restrictions" group, verify that "allow developer mode" is not selected. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "About phone". 
3. Tap "Software information". 
4. Keep tapping "Build number". 
5. Verify that message "Developer mode has been enabled" is displayed but "Developer options" is not available in Settings. 

If on the MDM console "allow developer mode" is selected, or on the Samsung Android device "Developer options" can be enabled by the user, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disallow developer mode. 

On the MDM console, for the device, in the "Knox restrictions" group, unselect "allow developer mode".'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(Legacy)'
  tag check_id: 'C-92933r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93617'
  tag rid: 'SV-103703r1_rule'
  tag stig_id: 'KNOX-09-000925'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-99861r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
