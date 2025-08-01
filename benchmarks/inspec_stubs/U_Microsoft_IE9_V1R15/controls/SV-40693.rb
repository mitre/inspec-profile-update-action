control 'SV-40693' do
  title 'Crash Detection must be enforced.'
  desc "The Turn off Crash Detection policy setting allows you to manage the crash detection feature of add-on management in Internet Explorer. If you enable this policy setting, a crash in Internet Explorer will be similar to one on a computer running Windows XP Professional Service Pack 1 and earlier; Windows Error Reporting will be invoked. If you disable this policy setting, the crash detection feature in add-on management will be functional. Because Internet Explorer crash report information could contain sensitive information from the computer's memory, this guide recommends configuring this option to Enabled unless experiencing frequent repeated crashes and need to report them for follow-up troubleshooting. In those cases, you could temporarily configure the setting to Disabled."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Turn off Crash Detection" must be “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions 

Criteria: If the value NoCrashDetection is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Turn off Crash Detection" to “Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39423r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15579'
  tag rid: 'SV-40693r1_rule'
  tag stig_id: 'DTBI715'
  tag gtitle: 'DTBI715 - Crash Detection'
  tag fix_id: 'F-34551r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
