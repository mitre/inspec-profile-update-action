control 'SV-235755' do
  title 'Extensions that are approved for use must be allowlisted if used.'
  desc 'By default, all extensions are allowed. However, if all extensions are blocked by setting the "ExtensionInstallBlockList" policy to "*," users can only install extensions defined in this policy.'
  desc 'check', 'This requirement for "Allow specific extensions to be installed" is not required; this is optional.

The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Extensions/Allow specific extensions to be installed" must be set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

"ExtensionInstallAllowlist" must be set as follows:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallAllowlist\\1 = "extension_id1"
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallAllowlist\\2 = "extension_id2"

If configured, the list of extensions for which Microsoft Edge allows to be installed may be allowlisted.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Extensions/Allow specific extensions to be installed" to "Enabled".  A list of allowlisted extensions may then be specified.'
  impact 0.3
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38974r862953_chk'
  tag severity: 'low'
  tag gid: 'V-235755'
  tag rid: 'SV-235755r862954_rule'
  tag stig_id: 'EDGE-00-000042'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-38937r766862_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
