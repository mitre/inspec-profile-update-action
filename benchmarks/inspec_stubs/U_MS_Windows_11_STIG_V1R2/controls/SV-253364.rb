control 'SV-253364' do
  title 'Simultaneous connections to the internet or a Windows domain must be limited.'
  desc 'Multiple network connections can provide additional attack vectors to a system and must be limited. The "Minimize the number of simultaneous connections to the Internet or a Windows Domain" setting prevents systems from automatically establishing multiple connections. When both wired and wireless connections are available, for example, the less preferred connection (typically wireless) will be disconnected.'
  desc 'check', 'The default behavior for "Minimize the number of simultaneous connections to the Internet or a Windows Domain" is "Enabled".

If it exists and is configured with a value of "0", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\\

Value Name: fMinimizeConnections

Value Type: REG_DWORD
Value: 1 (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior for "Minimize the number of simultaneous connections to the Internet or a Windows Domain" is "Enabled".

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Windows Connection Manager >> "Minimize the number of simultaneous connections to the Internet or a Windows Domain" to "Enabled".  Under "Options" set Minimize Policy Options to "3 = Prevent Wi-Fi When on Ethernet".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56817r829174_chk'
  tag severity: 'medium'
  tag gid: 'V-253364'
  tag rid: 'SV-253364r840183_rule'
  tag stig_id: 'WN11-CC-000055'
  tag gtitle: 'SRG-OS-000481-GPOS-00481'
  tag fix_id: 'F-56767r840183_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
