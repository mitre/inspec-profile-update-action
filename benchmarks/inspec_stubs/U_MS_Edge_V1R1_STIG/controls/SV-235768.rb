control 'SV-235768' do
  title 'Suggestions of similar web pages in the event of a navigation error must be disabled.'
  desc %q(This setting allows Microsoft Edge to issue a connection to a web service to generate URL and search suggestions for connectivity issues such as DNS errors.

If this policy is enabled, a web service is used to generate URL and search suggestions for network errors.

If this policy is disabled, no calls to the web service are made and a standard error page is shown.

If this policy is not configured, Microsoft Edge respects the user preference that is set under Services at edge://settings/privacy. Specifically, there is a "Suggest similar pages when a webpage can't be found" toggle, which the user can switch on or off. 

Note that if this policy has been enabled (AlternateErrorPagesEnabled), the "Suggest similar pages when a webpage can't be found setting" is turned on, but the user cannot change the setting by using the toggle. 

If this policy is disabled, the "Suggest similar pages when a webpage can't be found" setting is turned off, and the user cannot change the setting by using the toggle.)
  desc 'check', %q(The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Suggest similar pages when a webpage can't be found" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\SOFTWARE\Policies\Microsoft\Edge\Recommended

If the value for AlternateErrorPagesEnabled is not set to "REG_DWORD = 0", this is a finding.)
  desc 'fix', %q(Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Suggest similar pages when a webpage can't be found" to "disabled".)
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38987r626500_chk'
  tag severity: 'medium'
  tag gid: 'V-235768'
  tag rid: 'SV-235768r626523_rule'
  tag stig_id: 'EDGE-00-000056'
  tag gtitle: 'SRG-APP-000151'
  tag fix_id: 'F-38950r626501_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
