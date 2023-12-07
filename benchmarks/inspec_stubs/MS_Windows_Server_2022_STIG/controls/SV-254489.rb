control 'SV-254489' do
  title 'Windows Server 2022 User Account Control (UAC) must virtualize file and registry write failures to per-user locations.'
  desc 'UAC is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures non-UAC-compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run.'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2022 versus Server with Desktop Experience).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableVirtualization

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> User Account Control: Virtualize file and registry write failures to per-user locations to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57974r849281_chk'
  tag severity: 'medium'
  tag gid: 'V-254489'
  tag rid: 'SV-254489r849283_rule'
  tag stig_id: 'WN22-SO-000450'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-57925r849282_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
