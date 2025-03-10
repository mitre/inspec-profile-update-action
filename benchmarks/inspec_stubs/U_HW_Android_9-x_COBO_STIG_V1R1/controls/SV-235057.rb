control 'SV-235057' do
  title 'Honeywell Mobility Edge Android Pie devices work profile must be configured to disable automatic completion of workspace internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Honeywell Mobility Edge Android Pie devices' password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Chrome Browser in Honeywell Mobility Edge Android Pie devices Work Profile autofill setting.

This procedure is performed only on the MDM Administrator console. 
 
On the MDM console, for the Work Profile: 
1. Open the Chrome Browser Settings.
2. Verify "Enable autofill" is set to "off".
 
If on the MDM console autofill is set to "on" in the Chrome Browser Settings, this is a finding.'
  desc 'fix', 'Configure Chrome Browser in Honeywell Mobility Edge Android Pie devices Work Profile to disable autofill.
 
On the MDM console, for the Work Profile: 
1. Open the Chrome Browser Settings.
2. Set "Enable autofill" to "off".

Refer to the MDM documentation to determine how to configure Chrome Browser Settings.'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38245r623081_chk'
  tag severity: 'medium'
  tag gid: 'V-235057'
  tag rid: 'SV-235057r626530_rule'
  tag stig_id: 'HONW-09-009800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-38208r623082_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
