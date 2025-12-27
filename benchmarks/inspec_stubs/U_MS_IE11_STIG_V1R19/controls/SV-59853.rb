control 'SV-59853' do
  title 'Enhanced Protected Mode functionality must be enforced.'
  desc 'Enhanced Protected Mode provides additional protection against malicious websites by using 64-bit processes on 64-bit versions of Windows. For computers running at least Windows 8, Enhanced Protected Mode also limits the locations Internet Explorer can read from in the registry and the file system. If you enable this policy setting, Enhanced Protected Mode will be turned on. Any zone that has Protected Mode enabled will use Enhanced Protected Mode. Users will not be able to disable Enhanced Protected Mode. If you disable this policy setting, Enhanced Protected Mode will be turned off. Any zone that has Protected Mode enabled will use the version of Protected Mode introduced in Internet Explorer 7 for Windows Vista. If you do not configure this policy, users will be able to turn on or turn off Enhanced Protected Mode on the "Advanced" tab of the Internet Options dialog box.'
  desc 'check', %q(Note: If McAfee ENS Web Control is being used, this is Not Applicable.

The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page 'Turn on Enhanced Protected Mode' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main Criteria: If the value "Isolation" is REG_SZ = 'PMEM', this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page 'Turn on Enhanced Protected Mode' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49975r4_chk'
  tag severity: 'medium'
  tag gid: 'V-46987'
  tag rid: 'SV-59853r3_rule'
  tag stig_id: 'DTBI995-IE11'
  tag gtitle: 'DTBI995-IE11-Enhanced Protected Mode'
  tag fix_id: 'F-50711r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
