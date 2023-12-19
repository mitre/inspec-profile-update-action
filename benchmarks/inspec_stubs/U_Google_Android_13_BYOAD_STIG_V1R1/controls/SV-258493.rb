control 'SV-258493' do
  title 'The Google Android 13 work profile must be configured to disable automatic completion of workspace internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Android 13 device password, or who otherwise can unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the work profile Chrome Browser app on the Google Android 13 autofill setting.

This procedure is performed only on the EMM Administrator console. 
 
On the EMM console:

1. Open "Managed Configurations" section.
2. Select the Chrome Browser version from the work profile.
3. Verify "SearchSuggestEnabled" is turned "OFF".
 
If on the EMM console autofill is set to "On" in the Chrome Browser Settings, this is a finding.'
  desc 'fix', 'Configure the Chrome browser on the Google Android 13 device work profile to disable autofill.
 
On the EMM console:

1. Open "Managed Configurations" section.
2. Select the Chrome Browser version from the work profile.
3. Ensure "SearchSuggestEnabled" is turned "OFF".

Refer to the EMM documentation to determine how to configure Chrome Browser Settings.'
  impact 0.5
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62233r929293_chk'
  tag severity: 'medium'
  tag gid: 'V-258493'
  tag rid: 'SV-258493r929295_rule'
  tag stig_id: 'GOOG-13-710400'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62142r929294_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
