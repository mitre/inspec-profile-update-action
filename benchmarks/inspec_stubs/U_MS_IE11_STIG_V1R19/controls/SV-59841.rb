control 'SV-59841' do
  title 'When Enhanced Protected Mode is enabled, ActiveX controls must be disallowed to run in Protected Mode.'
  desc 'This setting prevents ActiveX controls from running in Protected Mode when Enhanced Protected Mode is enabled. When a user has an ActiveX control installed that is not compatible with Enhanced Protected Mode and a website attempts to load the control, Internet Explorer notifies the user and gives the option to run the website in regular Protected Mode. This policy setting disables this notification and forces all websites to run in Enhanced Protected Mode. Enhanced Protected Mode provides additional protection against malicious websites by using 64-bit processes on 64-bit versions of Windows. For computers running at least Windows 8, Enhanced Protected Mode also limits the locations Internet Explorer can read from in the registry and the file system. If you enable this policy setting, Internet Explorer will not give the user the option to disable Enhanced Protected Mode. All Protected Mode websites will run in Enhanced Protected Mode. If you disable or do not configure this policy setting, Internet Explorer notifies users and provides an option to run websites with incompatible ActiveX controls in regular Protected Mode.'
  desc 'check', %q(Note: If McAfee ENS Web Control is being used, this is Not Applicable.

The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page 'Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main Criteria: If the value "DisableEPMCompat" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page 'Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49971r3_chk'
  tag severity: 'medium'
  tag gid: 'V-46975'
  tag rid: 'SV-59841r2_rule'
  tag stig_id: 'DTBI985-IE11'
  tag gtitle: 'DTBI985-IE11-ActiveX controls in Enhanced Protected Mode'
  tag fix_id: 'F-50705r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001687']
  tag nist: ['SC-18 (2)']
end
