control 'SV-256893' do
  title 'Internet Explorer must be disabled for Windows 11.'
  desc 'Internet Explorer 11 (IE11) is not supported on Windows 11 semi-annual channel.'
  desc 'check', 'Determine if IE11 is installed or enabled on Windows 11 semi-annual channel.

If IE11 is installed or not disabled on Windows 11 semi-annual channel, this is a finding.

If IE11 is installed on an unsupported operating system and is enabled or installed, this is a finding.

For more information, visit: https://learn.microsoft.com/en-us/lifecycle/faq/internet-explorer-microsoft-edge#what-is-the-lifecycle-policy-for-internet-explorer-'
  desc 'fix', 'For Windows 11 semi-annual channel, remove or disable the IE11 application. 

To disable IE11 as a standalone browser:

Set the policy value for "Computer Configuration/Administrative Templates/Windows Components/Internet Explorer/Disable Internet Explorer 11 as a standalone browser" to "Enabled" with the option value set to "Never".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-60568r891288_chk'
  tag severity: 'medium'
  tag gid: 'V-256893'
  tag rid: 'SV-256893r892440_rule'
  tag stig_id: 'WN11-CC-000391'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-60511r891268_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
