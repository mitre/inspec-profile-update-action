control 'SV-235754' do
  title 'Extensions installation must be blocklisted by default.'
  desc 'List specific extensions that users cannot install in Microsoft Edge. When this policy is deployed, any extensions on this list that were previously installed will be disabled, and the user will not be able to enable them. If an item is removed from the list of blocked extensions, the extension is automatically reenabled anywhere it was previously installed.

Use "*" to block all extensions that are not explicitly listed in the allow list.

If this policy is not configured, users can install any extension in Microsoft Edge.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Extensions/Control which extensions cannot be installed" must be set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallBlocklist

If the value for "ExtensionInstallBlocklist" is not set to "REG_SZ = *", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Extensions/Control which extensions cannot be installed" to "Enabled". A list of blocklisted extensions may then be specified.'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38973r766858_chk'
  tag severity: 'medium'
  tag gid: 'V-235754'
  tag rid: 'SV-235754r766860_rule'
  tag stig_id: 'EDGE-00-000041'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38936r766859_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
