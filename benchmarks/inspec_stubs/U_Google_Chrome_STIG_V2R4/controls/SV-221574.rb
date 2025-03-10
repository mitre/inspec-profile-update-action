control 'SV-221574' do
  title 'Network prediction must be disabled.'
  desc 'Enables network prediction in Google Chrome and prevents users from changing this setting. If you enable or disable this setting, users cannot change or override this setting in Google Chrome. If this policy is left not set, this will be disabled but the user will be able to change it.'
  desc 'check', 'Universal method:
1. In the omnibox (address bar) type chrome://policy
2. If "NetworkPredictionOptions" is not displayed under the “Policy Name” column or it is not set to "2" under the “Policy Value” column, this is a finding.
Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the "NetworkPredictionOptions" value name does not exist or its value data is not set to "2," this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with gpedit.msc
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
Policy Name: Enable network prediction
Policy State: Enabled
Policy Value: Do not predict network actions on any network connection'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23289r415849_chk'
  tag severity: 'medium'
  tag gid: 'V-221574'
  tag rid: 'SV-221574r615937_rule'
  tag stig_id: 'DTBC-0025'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-23278r415850_fix'
  tag 'documentable'
  tag legacy: ['SV-57603', 'V-44769']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
