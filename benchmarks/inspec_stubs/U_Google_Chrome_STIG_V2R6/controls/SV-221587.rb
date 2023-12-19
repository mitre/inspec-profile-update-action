control 'SV-221587' do
  title 'Prompt for download location must be enabled.'
  desc 'If the policy is enabled, the user will be asked where to save each file before downloading. If the policy is disabled, downloads will start immediately, and the user will not be asked where to save the file. If the policy is not configured, the user will be able to change this setting.'
  desc 'check', 'Universal method:
1. In the omnibox (address bar) type chrome:// policy
2. If "PromptForDownloadLocation" is not displayed under the "Policy Name" column or it is not set to "true" under the "Policy Value" column, then this is a finding.
Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the "PromptForDownloadLocation" value name does not exist or its value data is not set to "1", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with gpedit.msc
2. Navigate to Policy Path:  Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
 Policy Name: Ask where to save each file before downloading
 Policy State:  Enabled
 Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23302r415888_chk'
  tag severity: 'medium'
  tag gid: 'V-221587'
  tag rid: 'SV-221587r615937_rule'
  tag stig_id: 'DTBC-0053'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-23291r415889_fix'
  tag 'documentable'
  tag legacy: ['SV-94633', 'V-79929']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
