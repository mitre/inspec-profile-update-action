control 'SV-235088' do
  title 'Honeywell Mobility Edge Android Pie devices work profile must be configured to disable automatic completion of workspace internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Honeywell Mobility Edge Android Pie devices' password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', %q(Review Chrome Browser in the Honeywell Android Pie device's Work Profile autofill setting.

This procedure is performed only on the MDM Administrator console. 
 
On the MDM console, for the Work Profile, do the following: 
1. Open the Chrome Browser Settings.
2. Verify "Enable autofill" is set to "Off".
 
If on the MDM console autofill is set to "On" in the Chrome Browser Settings, this is a finding.)
  desc 'fix', %q(Configure Chrome Browser in the Honeywell Android Pie device's Work Profile to disable autofill.
 
On the MDM console, for the Work Profile: 
1. Open the Chrome Browser Settings.
2. Set "Enable autofill" to "Off".

Refer to the MDM documentation to determine how to configure Chrome Browser Settings.)
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38307r623279_chk'
  tag severity: 'medium'
  tag gid: 'V-235088'
  tag rid: 'SV-235088r626527_rule'
  tag stig_id: 'HONW-09-009800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-38270r623280_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
