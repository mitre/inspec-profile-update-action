control 'SV-45107' do
  title 'Automatic configuration of Internet Explorer connections must be disallowed.'
  desc 'This setting specifies to automatically detect the proxy server settings used to connect to the Internet and customize Internet Explorer. This setting specifies that Internet Explorer use the configuration settings provided in a file by the system administrator. If you enable this policy setting, the user will not be able to do automatic configuration. You can import current connection settings using Internet Explorer Maintenance under Admin Templates using group policy editor. If you disable or do not configure this policy setting, the user will have the freedom to automatically configure these settings.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Disable changing Automatic Configuration settings" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel 

Criteria: If the value Autoconfig is REG_DWORD = 1 (Hex), this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Disable changing Automatic Configuration settings" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42464r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15490'
  tag rid: 'SV-45107r1_rule'
  tag stig_id: 'DTBI305'
  tag gtitle: 'DTBI305-Automatic configuration is not disabled'
  tag fix_id: 'F-38506r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
