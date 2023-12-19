control 'SV-221590' do
  title 'Safe Browsing Extended Reporting must be disabled.'
  desc %q(Enables Google Chrome's Safe Browsing Extended Reporting and prevents users from changing this setting. Extended Reporting sends some system information and page content to Google servers to help detect dangerous apps and sites.
If the setting is set to "True", then reports will be created and sent whenever necessary (such as when a security interstitial is shown).
If the setting is set to "False", reports will never be sent.
If this policy is set to "True" or "False", the user will not be able to modify the setting.
If this policy is left unset, the user will be able to change the setting and decide whether to send reports or not.)
  desc 'check', 'Universal method:
 1. In the omnibox (address bar) type chrome://policy
 2. If "SafeBrowsingExtendedReportingEnabled" is not displayed under the "Policy Name" column or it is not set to "False", this is a finding.
Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the "SafeBrowsingExtendedReportingEnabled" value name does not exist or its value data is not set to "0", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the “group policy editor” tool with gpedit.msc
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Safe Browsing settings\\
Policy Name: Enable Safe Browsing Extended Reporting
Policy State: Disabled
Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23305r415897_chk'
  tag severity: 'medium'
  tag gid: 'V-221590'
  tag rid: 'SV-221590r615937_rule'
  tag stig_id: 'DTBC-0057'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-23294r415898_fix'
  tag 'documentable'
  tag legacy: ['SV-96299', 'V-81585']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
