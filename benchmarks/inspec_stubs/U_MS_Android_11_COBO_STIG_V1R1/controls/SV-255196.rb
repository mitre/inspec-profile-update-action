control 'SV-255196' do
  title 'Microsoft Android 11 Work Profile must be configured to disable the autofill services.'
  desc "The autofill services allow the user to complete text inputs that could contain sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill services, an adversary who learns a user's Microsoft Android 11 device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill services to provide information unknown to the adversary. By disabling the autofill services, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated. 
 
Examples of apps that offer autofill services include Samsung Pass, Google, Dashlane, LastPass, and 1Password.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the Microsoft Android 11 work profile configuration settings to confirm that autofill services are disabled. 
 
This procedure is performed only on the EMM Administration console. 
 
On the EMM console:
1. Open "Set user restrictions".
2. Verify that "Disable autofill" is toggled to "On".
 
If on the EMM console "disallow autofill" is selected, this is a finding.'
  desc 'fix', 'Configure Microsoft Android 11 device work profile to disable the autofill services. 
 
On the EMM console:
1. Open "Set user restrictions".
2. Toggle "Disable autofill" to "On".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58809r869449_chk'
  tag severity: 'medium'
  tag gid: 'V-255196'
  tag rid: 'SV-255196r870704_rule'
  tag stig_id: 'MSFT-11-010000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-58753r869450_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
