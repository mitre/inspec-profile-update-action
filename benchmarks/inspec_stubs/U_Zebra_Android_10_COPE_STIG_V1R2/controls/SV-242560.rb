control 'SV-242560' do
  title 'Zebra Android 10 Work Profile must be configured to disable automatic completion of work space internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Zebra Android 10 device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Chrome Browser in the Zebra Android 10 Work Profile autofill setting.

This procedure is performed only on the MDM Administrator console. 
 
On the MDM console, for the Work Profile: 
1. Open the Chrome Browser Settings.
2. Verify "Enable autofill" is set to Off.
 
If on the MDM console autofill is set to On in the Chrome Browser Settings, this is a finding.'
  desc 'fix', 'Configure Chrome Browser in Zebra Android 10 Work Profile to disable autofill.
 
On the MDM console, for the Work Profile: 
1. Open the Chrome Browser Settings.
2. Set "Enable autofill" to Off.

Refer to the MDM documentation to determine how to configure Chrome Browser Settings.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COPE'
  tag check_id: 'C-45835r714523_chk'
  tag severity: 'medium'
  tag gid: 'V-242560'
  tag rid: 'SV-242560r714525_rule'
  tag stig_id: 'ZEBR-10-009800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-45792r714524_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
