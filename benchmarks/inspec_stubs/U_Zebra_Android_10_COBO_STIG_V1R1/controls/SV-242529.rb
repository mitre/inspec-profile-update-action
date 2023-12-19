control 'SV-242529' do
  title 'Zebra Android 10 Work Profile must be configured to disable the autofill services.'
  desc "The autofill services allow the user to complete text inputs that could contain sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill services, an adversary who learns a user's Zebra Android 10 device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill services to provide information unknown to the adversary. By disabling the autofill services, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated. 
 
Examples of apps that offer autofill services include Samsung Pass, Google, Dashlane, LastPass, and 1Password.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the Zebra Android 10 Workspace configuration settings to confirm that autofill services are disabled. 
 
This procedure is performed only on the MDM Administration Console. 
 
On the MDM console, for the Workspace, in the "Android user restrictions" group, under the work profile, verify that "disallow autofill" is selected. 
 
If on the MDM console "disallow autofill" is not selected, this is a finding.'
  desc 'fix', 'Configure Zebra Android 10 Workspace to disable the autofill services. 
 
On the MDM console, in the Android work profile restrictions, select "disallow autofill".'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45804r714430_chk'
  tag severity: 'medium'
  tag gid: 'V-242529'
  tag rid: 'SV-242529r714432_rule'
  tag stig_id: 'ZEBR-10-010000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-45761r714431_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
