control 'SV-103943' do
  title 'Samsung Android must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [DoD-approved commercial app repository, MDM server, mobile application store]: - disallow unknown app installation sources.'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review device configuration settings to confirm that installation from unauthorized application repositories is disallowed. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox restrictions" group, verify that "allow install unknown sources" is not selected. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Apps". 
3. Tap the Overflow menu (three vertical dots). 
4. Tap "Special Access". 
5. Tap "Install unknown apps". 
6. Tap a listed app. 
7. Verify that "Allow from this source" cannot be enabled. 

If on the MDM console "allow install unknown source" is selected, or on the Samsung Android device the user can enable "allow from this source" for an app, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disallow installation from unauthorized application repositories. 

On the MDM console, for the device, in the "Knox restrictions" group, unselect "allow install unknown sources".'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(Legacy)'
  tag check_id: 'C-93175r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93857'
  tag rid: 'SV-103943r1_rule'
  tag stig_id: 'KNOX-09-000135'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-100103r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
