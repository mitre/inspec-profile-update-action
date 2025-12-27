control 'SV-59497' do
  title 'Checking for signatures on downloaded programs must be enforced.'
  desc 'This policy setting allows you to manage whether Internet Explorer checks for digital signatures (which identifies the publisher of signed software and verifies it has not been modified or tampered with) on user computers before downloading executable programs. If you enable this policy setting, Internet Explorer will check the digital signatures of executable programs and display their identities before downloading them to the user computers. If you disable this policy setting, Internet Explorer will not check the digital signatures of executable programs or display their identities before downloading them to the user computers. If you do not configure this policy, Internet Explorer will not check the digital signatures of executable programs or display their identities before downloading them to the user computers.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> 'Check for signatures on downloaded programs' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Download Criteria: If the value "CheckExeSignatures" is REG_SZ = yes, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> 'Check for signatures on downloaded programs' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49799r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46633'
  tag rid: 'SV-59497r1_rule'
  tag stig_id: 'DTBI370-IE11'
  tag gtitle: 'DTBI370-IE11-Signature checking on downloaded programs'
  tag fix_id: 'F-50403r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
