control 'SV-250979' do
  title 'Apple iOS/iPadOS 15 must disable connections to Siri servers for the purpose of dictation.'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD sensitive information. Dictation information could contain sensitive DoD information and therefore should not leave the DoD control.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Disable connections to Siri servers for the purpose of dictation" is disabled.

This check procedure is performed on the device management tool.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Disable connections to Siri servers for the purpose of dictation" is checked.

If connections to Siri servers are not disabled for dictation, this is a finding.'
  desc 'fix', 'Configure the Apple iOS configuration profile to disable connections to Siri servers for the purpose of dictation. This a supervised-only control.

The procedure for implementing this control will vary depending on the MDM/EMM used by the mobile service provider.

In the MDM console, select "disable connections to Siri servers for the purpose of dictation".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54414r802026_chk'
  tag severity: 'medium'
  tag gid: 'V-250979'
  tag rid: 'SV-250979r802028_rule'
  tag stig_id: 'AIOS-15-014400'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54368r802043_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
