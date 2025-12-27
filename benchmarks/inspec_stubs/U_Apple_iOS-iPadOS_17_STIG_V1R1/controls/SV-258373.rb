control 'SV-258373' do
  title 'Apple iOS/iPadOS 17 must disable connections to Siri servers for the purpose of translation.'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DOD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DOD sensitive information. Translation information could contain sensitive DOD information and therefore should not leave the DOD control.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This check procedure is performed on the device management tool.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Disable connections to Siri servers for the purpose of translation" is checked.

If connections to Siri servers are not disabled for translation, this is a finding.'
  desc 'fix', 'Configure the Apple iOS configuration profile to disable connections to Siri servers for the purpose of translation. 

The procedure for implementing this control will vary depending on the MDM/EMM used by the mobile service provider.

In the MDM console, select "disable connections to Siri servers for the purpose of translation".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62114r927800_chk'
  tag severity: 'medium'
  tag gid: 'V-258373'
  tag rid: 'SV-258373r927802_rule'
  tag stig_id: 'AIOS-17-014500'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62038r927801_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
