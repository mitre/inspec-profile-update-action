control 'SV-221563' do
  title 'Extensions that are approved for use must be allowlisted.'
  desc 'The allowlist should only contain organizationally approved extensions. This is to prevent a user from accidently allowlisitng a malicious extension. This policy allows you to specify which extensions are not subject to the blacklist. A blacklist value of ‘*’ means all extensions are blacklisted and users can only install extensions listed in the allowlist. By default, no extensions are allowlisted. If all extensions have been blacklisted by policy, then the allowlist policy can be used to allow specific extensions to be installed. Administrators should determine which extensions should be allowed to be installed by their users. If no extensions are allowlisted, then no extensions can be installed when combined with blacklisting all extensions.'
  desc 'check', 'Universal method: 
1. In the omnibox (address bar) type chrome://policy 
2. If ExtensionInstallAllowlist is not displayed under the Policy Name column or it is not set to oiigbmnaadbkfbmpbfijlflahbdbdgdf or a list of administrator approved extension IDs, then this is a finding.

Windows method:
1. Start regedit
2. Navigate to the key HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallAllowlist
3. If the ExtensionInstallAllowlist key is not set to 1 and oiigbmnaadbkfbmpbfijlflahbdbdgdf or a list of administrator-approved extension IDs, then this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with gpedit.msc 
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Extensions\\
Policy Name: Configure extension installation allowlist
Policy State: Enabled
Policy Value: oiigbmnaadbkfbmpbfijlflahbdbdgdf

Note: oiigbmnaadbkfbmpbfijlflahbdbdgdfis the extension ID for scriptno (a commonly used Chrome extension), other extension IDs may vary.'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23278r684816_chk'
  tag severity: 'medium'
  tag gid: 'V-221563'
  tag rid: 'SV-221563r684818_rule'
  tag stig_id: 'DTBC-0006'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-23267r684817_fix'
  tag 'documentable'
  tag legacy: ['SV-57563', 'V-44729']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
