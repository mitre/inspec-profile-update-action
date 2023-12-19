control 'SV-43163' do
  title 'Check for publishers certificate revocation must be enforced.'
  desc "Check for publisher's certificate revocation options should be enforced to ensure all PKI signed objects are validated."
  desc 'check', 'Procedure: Open Internet Explorer. From the menu bar select Tools. From the Tools dropdown menu, select the Internet Options. From the Internet Options window, select the "Advanced" tab from the Advanced tab window, scroll down to the Security category, and verify the "check for publishers certificate revocation" box is selected. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
 
HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust Providers\\Software Publishing

Criteria: If the value State is REG_DWORD = 65536 (decimal), this is not a finding.'
  desc 'fix', %q(In the Internet Explorer Options, on the "Advanced" tab, scroll down to Security category, and select the "Check for publisher's certificate revocation" box.

NOTE: Manual entry for the value State, set to REG_DWORD = 65536, may first be required.)
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-41151r3_chk'
  tag severity: 'medium'
  tag gid: 'V-32808'
  tag rid: 'SV-43163r2_rule'
  tag stig_id: 'DTBI018'
  tag gtitle: 'DTBI018 - Publishers Certificate Revocation'
  tag fix_id: 'F-36699r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
