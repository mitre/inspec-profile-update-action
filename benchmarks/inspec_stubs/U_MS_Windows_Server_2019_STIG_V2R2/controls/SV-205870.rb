control 'SV-205870' do
  title 'Windows Server 2019 Windows Update must not obtain updates from other PCs on the Internet.'
  desc 'Windows Update can obtain updates from additional sources instead of Microsoft. In addition to Microsoft, updates can be obtained from and sent to PCs on the local network as well as on the Internet. This is part of the Windows Update trusted process, however to minimize outside exposure, obtaining updates from or sending to systems on the Internet must be prevented.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\\

Value Name: DODownloadMode

Value Type: REG_DWORD
Value: 0x00000000 (0) - No peering (HTTP Only)
0x00000001 (1) - Peers on same NAT only (LAN)
0x00000002 (2) - Local Network / Private group peering (Group)
0x00000063 (99) - Simple download mode, no peering (Simple)
0x00000064 (100) - Bypass mode, Delivery Optimization not used (Bypass)

A value of 0x00000003 (3), Internet, is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Delivery Optimization >> "Download Mode" to "Enabled" with any option except "Internet" selected.

Acceptable selections include:

Bypass (100)
Group (2)
HTTP only (0)
LAN (1)
Simple (99)'
  impact 0.3
  ref 'DPMS Target MS Windows Server 2019'
  tag check_id: 'C-6135r355972_chk'
  tag severity: 'low'
  tag gid: 'V-205870'
  tag rid: 'SV-205870r569188_rule'
  tag stig_id: 'WN19-CC-000260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6135r355973_fix'
  tag 'documentable'
  tag legacy: ['SV-103347', 'V-93259']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
