control 'SV-235755' do
  title 'Extensions that are approved for use must be allowlisted.'
  desc 'By default, all extensions are allowed. However, if all extensions are blocked by setting the "ExtensionInstallBlockList" policy to "*," users can only install extensions defined in this policy.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Extensions/Allow specific extensions to be installed" must be set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

"ExtensionInstallAllowlist" must be set as follows:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallAllowlist\\1 = "extension_id1"
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallAllowlist\\2 = "extension_id2"

If the value for "ExtensionInstallAllowlist" is not set, this is a finding.

If no extensions in the agency require whitelisting for use, this is Not Applicable.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Extensions/Allow specific extensions to be installed" to "Enabled".  A list of whitelisted extensions may then be specified.'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38974r626461_chk'
  tag severity: 'medium'
  tag gid: 'V-235755'
  tag rid: 'SV-235755r626523_rule'
  tag stig_id: 'EDGE-00-000042'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-38937r626462_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
