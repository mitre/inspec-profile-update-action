control 'SV-59483' do
  title 'Internet Explorer must be configured to use machine settings.'
  desc 'Users who change their Internet Explorer security settings could enable the execution of dangerous types of code from the Internet and websites listed in the Restricted Sites zone in the browser. This setting enforces consistent security zone settings to all users of the computer. Security zones control browser behavior at various websites and it is desirable to maintain a consistent policy for all users of a machine. This policy setting affects how security zone changes apply to different users. If you enable this policy setting, changes that one user makes to a security zone will apply to all users of that computer. If this policy setting is disabled or not configured, users of the same computer are allowed to establish their own security zone settings.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer 'Security Zones: Use only machine settings' must be 'Enabled'.  Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings Criteria: If the value "Security_HKLM_only" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer 'Security Zones: Use only machine settings' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49785r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46619'
  tag rid: 'SV-59483r1_rule'
  tag stig_id: 'DTBI320-IE11'
  tag gtitle: 'DTBI320-IE11-Security zone machine settings'
  tag fix_id: 'F-50389r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000345']
  tag nist: ['CM-5']
end
