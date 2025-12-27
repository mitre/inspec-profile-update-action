control 'SV-230104' do
  title 'The Motorola Android Pie work profile must be configured to disable automatic completion of work space internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Android Pie device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Chrome Browser in the Motorola Android Pie Work Profile autofill setting.

This procedure is performed only on the MDM Administrator console. 
 
On the MDM console, for the Work Profile: 
1. Open the Chrome Browser settings.
2. Verify "Enable autofill" is set to "Off".
 
If on the MDM console autofill is set to "On" in the Chrome Browser settings, this is a finding.'
  desc 'fix', 'Configure Chrome Browser in Motorola Android Pie Work Profile to disable autofill.
 
On the MDM console, for the Work Profile: 
1. Open the Chrome Browser settings.
2. Set "Enable autofill" to "Off".

Refer to the MDM documentation to determine how to configure Chrome Browser settings.'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-32419r538308_chk'
  tag severity: 'medium'
  tag gid: 'V-230104'
  tag rid: 'SV-230104r569708_rule'
  tag stig_id: 'MOTO-09-009800'
  tag gtitle: 'GOOG-09-009800'
  tag fix_id: 'F-32397r538309_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
