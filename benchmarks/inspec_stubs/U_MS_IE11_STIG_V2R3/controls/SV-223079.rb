control 'SV-223079' do
  title 'Checking for signatures on downloaded programs must be enforced.'
  desc 'This policy setting allows you to manage whether Internet Explorer checks for digital signatures (which identifies the publisher of signed software and verifies it has not been modified or tampered with) on user computers before downloading executable programs. If you enable this policy setting, Internet Explorer will check the digital signatures of executable programs and display their identities before downloading them to the user computers. If you disable this policy setting, Internet Explorer will not check the digital signatures of executable programs or display their identities before downloading them to the user computers. If you do not configure this policy, Internet Explorer will not check the digital signatures of executable programs or display their identities before downloading them to the user computers.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> 'Check for signatures on downloaded programs' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Download Criteria: If the value "CheckExeSignatures" is REG_SZ = yes, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> 'Check for signatures on downloaded programs' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24752r428787_chk'
  tag severity: 'medium'
  tag gid: 'V-223079'
  tag rid: 'SV-223079r428789_rule'
  tag stig_id: 'DTBI370-IE11'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-24740r428788_fix'
  tag 'documentable'
  tag legacy: ['SV-59497', 'V-46633']
  tag cci: ['CCI-001779']
  tag nist: ['CM-8 b']
end
