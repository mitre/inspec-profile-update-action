control 'SV-235719' do
  title 'User control of proxy settings must be disabled.'
  desc "This action configures the proxy settings for Microsoft Edge.

If this policy is enabled, Microsoft Edge ignores all proxy-related options specified from the command line.

If this policy is not configured, users can choose their own proxy settings.

This policy overrides the following individual policies:
- ProxyMode 
- ProxyPacUrl 
- ProxyServer 
- ProxyBypassList

Setting the ProxySettings policy accepts the following fields:
- ProxyMode, which allows for the proxy server used by Microsoft Edge to be specified and prevents users from changing proxy settings
- ProxyPacUrl, a URL to a proxy .pac file
- ProxyServer, a URL for the proxy server
- ProxyBypassList, a list of proxy hosts that Microsoft Edge bypasses

For ProxyMode, the following values have the noted impact:
- direct, a proxy is never used and all other fields are ignored.
- system, the system's proxy is used and all other fields are ignored.
- auto_detect, all other fields are ignored.
- fixed_server, the ProxyServer and ProxyBypassList fields are used.
- pac_script, the ProxyPacUrl and ProxyBypassList fields are used."
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Proxy server/ProxySettings" must be set to one of the following options: "ProxyMode", "ProxyPacUrl", "ProxyServer", or "ProxyBypassList".

If "ProxyMode" is used, one of the following must be set: "direct", "system", "auto_detect", "fixed_server", "pac_script"

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ProxySettings" is not set to one of the above selections, this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Proxy server/ProxySettings" must be set to "ProxyMode", "ProxyPacUrl", "ProxyServer", or "ProxyBypassList".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38938r626353_chk'
  tag severity: 'medium'
  tag gid: 'V-235719'
  tag rid: 'SV-235719r626523_rule'
  tag stig_id: 'EDGE-00-000001'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-38901r626354_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
