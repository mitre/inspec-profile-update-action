control 'SV-254639' do
  title 'Apple iOS/iPadOS 16 must disable connections to Siri servers for the purpose of translation.'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD sensitive information. Translation information could contain sensitive DoD information and therefore should not leave the DoD control.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This check procedure is performed on the device management tool.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Disable connections to Siri servers for the purpose of translation" is checked.

If connections to Siri servers are not disabled for translation, this is a finding.'
  desc 'fix', 'Configure the Apple iOS configuration profile to disable connections to Siri servers for the purpose of translation. 

The procedure for implementing this control will vary depending on the MDM/EMM used by the mobile service provider.

In the MDM console, select "disable connections to Siri servers for the purpose of translation".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58250r862171_chk'
  tag severity: 'medium'
  tag gid: 'V-254639'
  tag rid: 'SV-254639r862232_rule'
  tag stig_id: 'AIOS-16-014500'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58196r862231_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000097', 'CCI-000370']
  tag nist: ['CM-6 b', 'AC-20 (2)', 'CM-6 (1)']
end
