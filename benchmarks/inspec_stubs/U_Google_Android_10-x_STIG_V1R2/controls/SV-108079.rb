control 'SV-108079' do
  title 'Google Android 10 work profile must be configured to disable automatic completion of work space Internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Google Android 10 device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Chrome Browser in Google Android 10 Work Profile autofill setting.

This procedure is performed only on the MDM Administrator console. 

On the MDM console, for the Work Profile, do the following: 
1. Open the Chrome Browser Settings.
2. Verify "Enable autofill" is set to off.

If on the MDM console autofill is set to on in the Chrome Browser Settings, this is a finding.'
  desc 'fix', 'Configure Chrome Browser in Google Android 10 Work Profile to disable autofill.

On the MDM console, for the Work Profile, do the following: 
1. Open the Chrome Browser Settings.
2. Set "Enable autofill" to off.

Refer to the MDM documentation to determine how to configure Chrome Browser Settings.'
  impact 0.5
  ref 'DPMS Target Google Android 10.x'
  tag check_id: 'C-97815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-98975'
  tag rid: 'SV-108079r1_rule'
  tag stig_id: 'GOOG-10-009800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-104651r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
