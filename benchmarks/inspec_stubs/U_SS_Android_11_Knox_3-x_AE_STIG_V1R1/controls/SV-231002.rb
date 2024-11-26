control 'SV-231002' do
  title 'Samsung Android Work Environment must be configured to disable the autofill services.'
  desc "The autofill services allow the user to complete text inputs that could contain sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of autofill services, an adversary who learns a user's Samsung Android device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the autofill services to provide information unknown to the adversary. By disabling the autofill services, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

Examples of apps that offer autofill services include Samsung Pass, Google, Dashlane, LastPass, and 1Password.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if autofill services are disabled.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

This policy cannot be enforced on a Legacy deployment and is a permanent finding.

On the management tool, in the Work Environment restrictions section, verify that "Autofill services" is set to "Disallow".

For COPE: On the Samsung Android device: 
1. Open Settings >> Work profile >> More settings >> Keyboard and input >> Autofill service.
2. Verify that no Autofill services are listed.

For COBO: On the Samsung Android device: 
1. Open Settings >> General management >> Language and input >> Autofill service.
2. Verify that no Autofill services are listed.

If on the management tool "Autofill services" is not set to "Disallow", or on the Samsung Android device autofill services are listed, this is a finding.'
  desc 'fix', 'Configure the Samsung Android Work Environment to disable autofill services.

On the management tool, in the Work Environment restrictions section, set "Autofill services" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33932r592498_chk'
  tag severity: 'medium'
  tag gid: 'V-231002'
  tag rid: 'SV-231002r607691_rule'
  tag stig_id: 'KNOX-11-019700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33905r592499_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
