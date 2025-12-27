control 'SV-250445' do
  title 'Google Android 12 work profile must be configured to disable automatic completion of work space Internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Android 12 device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the work profile Chrome Browser app on the Google Android 12 autofill setting.

This procedure is performed only on the EMM Administrator console. 
 
On the EMM console:

COPE:

1. Open "Managed Configurations" section.
2. Select the Chrome Browser version from the work profile.
3. Verify that "SearchSuggestEnabled" is turned OFF.
 
If on the EMM console autofill is set to On in the Chrome Browser Settings, this is a finding.'
  desc 'fix', 'Configure the Chrome browser on the Google Android 12 device Work Profile to disable autofill.
 
On the EMM console:

COPE:

1. Open "Managed Configurations" section.
2. Select the Chrome Browser version from the work profile.
3. Ensure "SearchSuggestEnabled" is turned OFF.

Refer to the EMM documentation to determine how to configure Chrome Browser Settings.'
  impact 0.5
  ref 'DPMS Target Google Android 12 COPE'
  tag check_id: 'C-53880r802689_chk'
  tag severity: 'medium'
  tag gid: 'V-250445'
  tag rid: 'SV-250445r802691_rule'
  tag stig_id: 'GOOG-12-010400'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-53834r802690_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
