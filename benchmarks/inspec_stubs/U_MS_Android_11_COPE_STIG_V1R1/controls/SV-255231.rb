control 'SV-255231' do
  title 'Microsoft Android 11 Work Profile must be configured to disable automatic completion of work space internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Microsoft Android 11 device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Chrome Browser in Microsoft Android 11 Work Profile autofill setting.

This procedure is performed only on the EMM Administrator console. 
 
On the EMM console:
1. Open "Managed Configurations" section.
2. Select the Chrome Browser version from the work profile.
3. Verify that "SearchSuggestEnabled" is turned off.
 
If on the EMM console autofill is set to on in the Chrome Browser Settings, this is a finding.'
  desc 'fix', 'Configure Chrome Browser in Microsoft Android 11 device Work Profile to disable autofill.
 
On the EMM console:
1. Open "Managed Configurations" section.
2. Select the Chrome Browser version from the work profile.
3. Ensure "SearchSuggestEnabled" is turned off.

Refer to the EMM documentation to determine how to configure Chrome Browser Settings.'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58844r870810_chk'
  tag severity: 'medium'
  tag gid: 'V-255231'
  tag rid: 'SV-255231r870812_rule'
  tag stig_id: 'MSFT-11-009800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-58788r869309_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
