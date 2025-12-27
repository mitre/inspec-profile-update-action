control 'SV-102977' do
  title 'Samsung Android must be configured to disable the autofill services.'
  desc "The autofill services allow the user to complete text inputs that could contain sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill services, an adversary who learns a user's Samsung Android device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill services to provide information unknown to the adversary. By disabling the autofill services, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated. 

Examples of apps that offer autofill services include Samsung Pass, Google, Dashlane, LastPass, and 1Password.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review device configuration settings to confirm that autofill services are disabled. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Android user restrictions" group, verify that "disallow autofill" is selected. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "General management". 
3. Tap "Language and input". 
4. Verify that "Autofill service" is not present. 

If on the MDM console "disallow autofill" is selected, or on the Samsung Android device "Autofill service" is present, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable the autofill services. 

On the MDM console, for the device, in the "Android user restrictions" group, select "disallow autofill".'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(AE)'
  tag check_id: 'C-92195r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92889'
  tag rid: 'SV-102977r1_rule'
  tag stig_id: 'KNOX-09-000610'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-99133r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
