control 'SV-258436' do
  title 'The Google Android 14 work profile must be configured to disable the autofill services.'
  desc "The autofill services allow the user to complete text inputs that could contain sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill services, an adversary who learns a user's Android 14 device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill services to provide information unknown to the adversary. By disabling the autofill services, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated. 
 
Examples of apps that offer autofill services include Samsung Pass, Google, Dashlane, LastPass, and 1Password.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the Google Android 14 work profile configuration settings to confirm that autofill services are disabled. 
 
This procedure is performed only on the EMM Administration console. 
 
On the EMM console:

COPE:

1. Open "Set user restrictions".
2. Verify "Disable autofill" is toggled to "ON".
 
If on the EMM console "disallow autofill" is not selected, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device work profile to disable the autofill services. 
 
On the EMM console:

COPE:

1. Open "Set user restrictions".
2. Toggle "Disable autofill" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 14 COPE'
  tag check_id: 'C-62177r928331_chk'
  tag severity: 'medium'
  tag gid: 'V-258436'
  tag rid: 'SV-258436r928333_rule'
  tag stig_id: 'GOOG-14-010500'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62101r928332_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
