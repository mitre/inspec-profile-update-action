control 'SV-230105' do
  title 'Motorola Android Pie Work Profile must be configured to disable the autofill services.'
  desc "The autofill services allow the user to complete text inputs that could contain sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill services, an adversary who learns a user's Android Pie device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill services to provide information unknown to the adversary. By disabling the autofill services, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated. 
 
Examples of apps that offer autofill services include Samsung Pass, Google, Dashlane, LastPass, and 1Password.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the Motorola Android Pie Workspace configuration settings to confirm that autofill services are disabled. 
 
This procedure is performed only on the MDM Administration console. 
 
On the MDM console, for the Workspace, in the "Android user restrictions" group, under the work profile, verify that "Disallow autofill" is selected. 
 
If on the MDM console "Disallow autofill" is not selected, this is a finding.'
  desc 'fix', 'Configure Motorola Android Pie Workspace to disable the autofill services. 
 
On the MDM console, in the Android work profile restrictions, select "Disallow autofill".'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-58178r859883_chk'
  tag severity: 'medium'
  tag gid: 'V-230105'
  tag rid: 'SV-230105r859885_rule'
  tag stig_id: 'MOTO-09-010000'
  tag gtitle: 'GOOG-09-010000'
  tag fix_id: 'F-58127r859884_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
