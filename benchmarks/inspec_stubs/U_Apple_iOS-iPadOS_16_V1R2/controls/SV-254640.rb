control 'SV-254640' do
  title 'Apple iOS/iPadOS 16 must disable copy/paste of data from managed to unmanaged applications.'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD sensitive information.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Require managed pasteboard" is set to "True".

If "Require managed pasteboard" is not set to "True", this is a finding.'
  desc 'fix', 'Configure the Apple iOS configuration profile to disable copy/paste of data from managed to unmanaged applications.

The procedure for implementing this control will vary depending on the MDM/EMM used by the mobile service provider.

In the MDM console, set "Require managed pasteboard" to "True".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58251r862174_chk'
  tag severity: 'medium'
  tag gid: 'V-254640'
  tag rid: 'SV-254640r862234_rule'
  tag stig_id: 'AIOS-16-014600'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58197r862233_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000097', 'CCI-000370']
  tag nist: ['CM-6 b', 'AC-20 (2)', 'CM-6 (1)']
end
