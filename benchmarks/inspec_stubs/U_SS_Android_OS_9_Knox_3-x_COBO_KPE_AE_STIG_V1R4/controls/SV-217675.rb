control 'SV-217675' do
  title 'Samsung Android must be configured to disable automatic completion of Samsung Internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Samsung Android device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review device configuration settings to confirm that automatic completion of Samsung Internet app text input is disabled. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox restrictions" group, verify that "allow autofill" is not selected. 

On the Samsung Android device, do the following: 
1. From the "Personal" App screen, launch the "Samsung Internet" app. 
2. From the collapsed menu icon (three horizontal bars) on the toolbar, tap "Settings". 
3. Tap "Privacy and security". 
4. Verify that "Autofill forms" is disabled and cannot be enabled. 

If on the MDM console "allow autofill" is selected, or on the Samsung Android device "Autofill forms" can be enabled by the user, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable automatic completion of Samsung Internet app text input. 

On the MDM console, for the device, in the "Knox restrictions" group, unselect "allow autofill".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18894r362054_chk'
  tag severity: 'medium'
  tag gid: 'V-217675'
  tag rid: 'SV-217675r388482_rule'
  tag stig_id: 'KNOX-09-000580'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18892r362055_fix'
  tag 'documentable'
  tag legacy: ['SV-102975', 'V-92887']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
