control 'SV-59677' do
  title 'Crash Detection management must be enforced.'
  desc "The 'Turn off Crash Detection' policy setting allows you to manage the crash detection feature of add-on management in Internet Explorer. A crash report could contain sensitive information from the computer's memory. If you enable this policy setting, a crash in Internet Explorer will be similar to one on a computer running Windows XP Professional Service Pack 1 and earlier, where Windows Error Reporting will be invoked. If you disable this policy setting, the crash detection feature in add-on management will be functional."
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> 'Turn off Crash Detection' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key:HKLM\Software\Policies\Microsoft\Internet Explorer\Restrictions Criteria: If the value "NoCrashDetection" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> 'Turn off Crash Detection' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49903r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46811'
  tag rid: 'SV-59677r1_rule'
  tag stig_id: 'DTBI715-IE11'
  tag gtitle: 'DTBI715-IE11-Crash Detection'
  tag fix_id: 'F-50561r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
