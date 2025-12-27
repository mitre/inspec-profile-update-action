control 'SV-250981' do
  title 'Apple iOS/iPadOS 15 must disable copy/paste of data from managed to unmanaged applications.'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD sensitive information. Translation information could contain sensitive DoD information and therefore should not leave the DoD control.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Require managed pasteboard" is set to "True".

This check procedure is performed on the device management tool.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Require managed pasteboard" is set to "True".

If "Require managed pasteboard" is not set to "True", this is a finding.'
  desc 'fix', 'Configure the Apple iOS configuration profile to disable copy/paste of data from managed to unmanaged applications.

The procedure for implementing this control will vary depending on the MDM/EMM used by the mobile service provider.

In the MDM console, set "Require managed pasteboard" to "True".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54416r802032_chk'
  tag severity: 'medium'
  tag gid: 'V-250981'
  tag rid: 'SV-250981r802034_rule'
  tag stig_id: 'AIOS-15-014600'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54370r802045_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
