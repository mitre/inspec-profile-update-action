control 'SV-221592' do
  title 'Chrome Cleanup must be disabled.'
  desc 'If set to “False”, prevents Chrome Cleanup from scanning the system for unwanted software and performing cleanups. Manually triggering Chrome Cleanup from chrome://settings/cleanup is disabled.
If set to “True” or unset, Chrome Cleanup periodically scans the system for unwanted software and should any be found, will ask the user if they wish to remove it. Manually triggering Chrome Cleanup from chrome://settings is enabled.
This policy is available only on Windows instances that are joined to a Microsoft Active Directory domain.'
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy
 2. If "ChromeCleanupEnabled" is not displayed under the "Policy Name" column or it is not set to "False", this is a finding.
Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the "ChromeCleanupEnabled" value name does not exist or its value data is not set to "0", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the “group policy editor” tool with gpedit.msc
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome
Policy Name: Enables Chrome Cleanup on Windows
Policy State: Disabled
Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23307r415903_chk'
  tag severity: 'medium'
  tag gid: 'V-221592'
  tag rid: 'SV-221592r615937_rule'
  tag stig_id: 'DTBC-0060'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-23296r415904_fix'
  tag 'documentable'
  tag legacy: ['SV-96305', 'V-81591']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
