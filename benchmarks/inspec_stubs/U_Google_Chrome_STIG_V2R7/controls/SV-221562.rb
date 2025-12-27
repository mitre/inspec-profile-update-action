control 'SV-221562' do
  title 'Extensions installation must be blocklisted by default.'
  desc "Extensions are developed by third party sources and are designed to extend Google Chrome's functionality. An extension can be made by anyone, to do and access almost anything on a system; this means they pose a high risk to any system that would allow all extensions to be installed by default. Allows you to specify which extensions the users can NOT install. Extensions already installed will be removed if blocklisted. A blocklist value of '*' means all extensions are blocklisted unless they are explicitly listed in the allowlist. If this policy is left not set the user can install any extension in Google Chrome."
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy 
 2. If ExtensionInstallBlocklist is not displayed under the Policy Name column or it is not set to * under the Policy Value column, then this is a finding.

Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallBlocklist
 3. If the a registry value name of 1 does not exist under that key or its value is not set to *, then this is a finding.'
  desc 'fix', 'Windows group policy:
 1. Open the group policy editor tool with gpedit.msc 
 2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Extensions\\
 Policy Name: Configure extension installation blocklist
 Policy State: Enabled
 Policy Value: *'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23277r684813_chk'
  tag severity: 'medium'
  tag gid: 'V-221562'
  tag rid: 'SV-221562r684815_rule'
  tag stig_id: 'DTBC-0005'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-23266r684814_fix'
  tag 'documentable'
  tag legacy: ['SV-57561', 'V-44727']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
