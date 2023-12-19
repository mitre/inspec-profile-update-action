control 'SV-45152' do
  title 'First Run Wizard settings must be established for a home page.'
  desc %q(This policy setting prevents Internet Explorer from running the First Run Wizard the first time a user starts the browser after installing Internet Explorer or Windows. If this policy setting is enabled, IE is configurable in two ways: 1) Skip the First Run Wizard, and go directly to the user's home page, or 2) Skip the First Run Wizard, and go directly to the "Welcome to Internet Explorer" web page. If this policy setting is disabled or not configured, Internet Explorer may run the First Run Wizard the first time the browser is started after installation and provide users the ability to configure IE outside of environment policy. Starting with Windows 8, the "Welcome to Internet Explorer" web page is not available. The user's home page will display regardless of which option is chosen.)
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Prevent running First Run Wizard" must be "Enabled", and "Go directly to home page" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main 

Criteria: If the value DisableFirstRunCustomize is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Prevent running First Run Wizard" to "Enabled", and select "Go directly to home page" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42495r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17296'
  tag rid: 'SV-45152r1_rule'
  tag stig_id: 'DTBI010'
  tag gtitle: 'DTBI010 - Prevent performance of First Run Customize setting'
  tag fix_id: 'F-38548r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
