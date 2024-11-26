control 'SV-221594' do
  title 'Google Cast must be disabled.'
  desc 'If this policy is set to ”True” or is not set, Google Cast will be enabled, and users will be able to launch it from the app menu, page context menus, media controls on Cast-enabled websites, and (if shown) the “Cast toolbar” icon.
If this policy set to ”False”, Google Cast will be disabled.'
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy
 2. If "EnableMediaRouter" is not displayed under the "Policy Name" column or it is not set to "False", this is a finding.
Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the "EnableMediaRouter" value name does not exist or its value data is not set to "0", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the “group policy editor” tool with gpedit.msc
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Google Cast
Policy Name: Enable Google Cast
Policy State: Disabled
Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23309r415909_chk'
  tag severity: 'medium'
  tag gid: 'V-221594'
  tag rid: 'SV-221594r615937_rule'
  tag stig_id: 'DTBC-0063'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23298r415910_fix'
  tag 'documentable'
  tag legacy: ['SV-96311', 'V-81597']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
