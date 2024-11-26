control 'SV-258697' do
  title 'The Samsung Android device work profile must be configured to disable automatic completion of work space internet browser text input.'
  desc "The autofill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill functionality, an adversary who learns a user's Android 14 device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill feature to provide information unknown to the adversary. By disabling the autofill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the work profile Chrome Browser app on the Samsung Android 14 autofill setting.

This validation procedure is performed on the management tool.

On the management tool:
1. Open "Managed Configurations" section.
2. Select the Chrome Browser version from the work profile.
3. Verify "PasswordManagerEnabled" is turned "OFF".
4. Verify "AutofillAddressEnabled" is turned "OFF".
5. Verify "AutofillCreditCardEnabled" is turned "OFF".

If on the management tool any of the browser autofill settings are set to "On" in the Chrome Browser Settings, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 14 device to disable the autofill functionality.

The required configuration is the default configuration when the device is enrolled. If the device configuration is changed, use the following procedure to bring the device back into compliance:

On the management tool:
1. Open the "Managed configurations" section.
2. Select the Chrome Browser version from the work profile.
3. Ensure "PasswordManagerEnabled" is turned "OFF".
4. Ensure "AutofillAddressEnabled" is turned "OFF".
5. Ensure "AutofillCreditCardEnabled" is turned "OFF".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62437r931289_chk'
  tag severity: 'medium'
  tag gid: 'V-258697'
  tag rid: 'SV-258697r931291_rule'
  tag stig_id: 'KNOX-14-225050'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62346r931290_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
