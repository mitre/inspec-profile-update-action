control 'SV-45116' do
  title 'Check for publishers certificate revocation must be enforced.'
  desc "Check for publisher's certificate revocation options should be enforced to ensure all PKI signed objects are validated."
  desc 'check', %q(Open Internet Explorer. From the menu bar, select Tools. From the Tools drop-down menu, select Internet Options. From the Internet Options window, select the "Advanced" tab, from the Advanced tab window, scroll down to the Security category, and verify the "Check for publisher's certificate revocation" box is selected. Procedure: Use the Windows Registry Editor to navigate to the following key: HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing Criteria: If the value "State" is REG_DWORD = 23C00, this is not a finding.)
  desc 'fix', %q(Open Internet Explorer. From the menu bar, select Tools. From the Tools drop-down menu, select Internet Options. From the Internet Options window, select the "Advanced" tab from the Advanced tab window, scroll down to the Security category, and select the "Check for publisher's certificate revocation" box.

Note: Manual entry in the registry key: HKCU\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\Software Publishing for the value "State", set to REG_DWORD = 23C00, may first be required.)
  impact 0.3
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42471r5_chk'
  tag severity: 'low'
  tag gid: 'V-32808'
  tag rid: 'SV-45116r4_rule'
  tag stig_id: 'DTBI018'
  tag gtitle: 'DTBI018 - Publishers Certificate Revocation'
  tag fix_id: 'F-38512r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
