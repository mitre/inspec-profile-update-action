control 'SV-252875' do
  title 'Zebra Android 11 work profile must be configured to disable automatic completion of work space internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Zebra Android 11 device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Chrome Browser in Zebra Android 11 Work Profile autofill setting.

This procedure is performed only on the EMM Administrator console. 
 
On the EMM console:
1. Open "Managed Configurations" section.
2. Select the Chrome Browser version from the work profile.
3.Verify that "SearchSuggestEnabled" is turned off.
 
If on the EMM console autofill is set to "On" in the Chrome Browser Settings, this is a finding.'
  desc 'fix', 'Configure Chrome Browser in Zebra Android 11 device Work Profile to disable autofill.
 
On the EMM console:
1. Open "Managed Configurations" section.
2. Select the Chrome Browser version from the work profile.
3. Ensure "SearchSuggestEnabled" is turned off.

Refer to the EMM documentation to determine how to configure Chrome Browser Settings.'
  impact 0.5
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56331r820550_chk'
  tag severity: 'medium'
  tag gid: 'V-252875'
  tag rid: 'SV-252875r820552_rule'
  tag stig_id: 'ZEBR-11-009800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-56281r820551_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
