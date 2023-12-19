control 'SV-221580' do
  title 'Safe Browsing must be enabled.'
  desc "Allows you to control whether Google Chrome's Safe Browsing feature is enabled and the mode it operates in.

If this policy is set to 'NoProtection' (value 0), Safe Browsing is never active.

If this policy is set to 'StandardProtection' (value 1, which is the default), Safe Browsing is always active in the standard mode.

If this policy is set to 'EnhancedProtection' (value 2), Safe Browsing is always active in the enhanced mode, which provides better security, but requires sharing more browsing information with Google."
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy 
 2. If SafeBrowsingProtectionLevel is not displayed under the Policy Name column or it is not set to 1 or 2 under the Policy Value column, then this is a finding.

Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the SafeBrowsingProtectionLevel value name does not exist or its value data is not set to 1 or 2, then this is a finding.'
  desc 'fix', 'Windows group policy:
 1. Open the “group policy editor” tool with gpedit.msc
 2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Safe Browsing Settings
 Policy Name: Safe Browsing Protection Level
 Policy State: Enabled
 Policy Value: "(1) Safe Browsing is active in the standard mode", or "(2) Safe Browsing is active in the enhanced mode. This mode provides better security, but requires sharing more browsing information with Google".'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23295r862941_chk'
  tag severity: 'medium'
  tag gid: 'V-221580'
  tag rid: 'SV-221580r862943_rule'
  tag stig_id: 'DTBC-0038'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-23284r862942_fix'
  tag 'documentable'
  tag legacy: ['SV-57625', 'V-44791']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
