control 'SV-258374' do
  title 'Apple iOS/iPadOS 17 must disable copy/paste of data from managed to unmanaged applications.'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DOD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DOD sensitive information.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Require managed pasteboard" is set to "True".

If "Require managed pasteboard" is not set to "True", this is a finding.'
  desc 'fix', 'Configure the Apple iOS configuration profile to disable copy/paste of data from managed to unmanaged applications.

The procedure for implementing this control will vary depending on the MDM/EMM used by the mobile service provider.

In the MDM console, set "Require managed pasteboard" to "True".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62115r927803_chk'
  tag severity: 'medium'
  tag gid: 'V-258374'
  tag rid: 'SV-258374r927805_rule'
  tag stig_id: 'AIOS-17-014600'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62039r927804_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
