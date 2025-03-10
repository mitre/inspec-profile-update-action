control 'SV-217764' do
  title 'Samsung Android Workspace must be configured to disable the autofill services.'
  desc "The autofill services allow the user to complete text inputs that could contain sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill services, an adversary who learns a user's Samsung Android device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill services to provide information unknown to the adversary. By disabling the autofill services, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated. 

Examples of apps that offer autofill services include Samsung Pass, Google, Dashlane, LastPass, and 1Password.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the Samsung Android Workspace configuration settings to confirm that autofill services are disabled. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the Workspace, in the "Android user restrictions" group, verify that "disallow autofill" is selected. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Workspace". 
3. Tap "More settings". 
4. Tap "Keyboard and input". 
5. Verify that "Autofill service" is not present. 

If on the MDM console "disallow autofill" is selected, or on the Samsung Android device "Autofill service" is present, this is a finding.'
  desc 'fix', 'Configure Samsung Android Workspace to disable the autofill services. 

On the MDM console, in the Android user restrictions, select "disallow autofill".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE AE'
  tag check_id: 'C-18981r362585_chk'
  tag severity: 'medium'
  tag gid: 'V-217764'
  tag rid: 'SV-217764r388482_rule'
  tag stig_id: 'KNOX-09-000620'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18979r362586_fix'
  tag 'documentable'
  tag legacy: ['SV-103877', 'V-93791']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
