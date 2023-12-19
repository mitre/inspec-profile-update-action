control 'SV-251580' do
  title 'Firefox feedback reporting must be disabled.'
  desc 'Disable the menus for reporting sites (Submit Feedback, Report Deceptive Site). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to advertising software or browser plug-ins that are not related to requirements or provide a wide array of functionality not required for every mission but that cannot be disabled.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "DisableFeedbackCommands" is not displayed under Policy Name or the Policy Value is not "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\
Policy Name: Disable Feedback Commands
Policy State: Enabled

macOS "plist" file:
<key>DisableFeedbackCommands</key>
  <true/>

Linux "policies.json" file:
Add the following in the policies section:
"DisableFeedbackCommands": true'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55015r807210_chk'
  tag severity: 'medium'
  tag gid: 'V-251580'
  tag rid: 'SV-251580r879587_rule'
  tag stig_id: 'FFOX-00-000036'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54969r807211_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
