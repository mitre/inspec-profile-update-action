control 'SV-254357' do
  title 'Windows Server 2022 Windows Update must not obtain updates from other PCs on the internet.'
  desc 'Windows Update can obtain updates from additional sources instead of Microsoft. In addition to Microsoft, updates can be obtained from and sent to PCs on the local network as well as on the internet. This is part of the Windows Update trusted process; however, to minimize outside exposure, obtaining updates from or sending to systems on the internet must be prevented.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\\

Value Name: DODownloadMode

Value Type: REG_DWORD
Value: 0x00000000 (0) - No peering (HTTP Only)
0x00000001 (1) - Peers on same NAT only (LAN)
0x00000002 (2) - Local Network / Private group peering (Group)
0x00000063 (99) - Simple download mode, no peering (Simple)

A value of 0x00000003 (3), Internet, is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Delivery Optimization >> Download Mode to "Enabled" with any option except "Internet" selected.

Acceptable selections include:

HTTP only (0)
LAN (1)
Group (2)
Internet (3)
Simple (99)'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57842r890543_chk'
  tag severity: 'low'
  tag gid: 'V-254357'
  tag rid: 'SV-254357r890545_rule'
  tag stig_id: 'WN22-CC-000260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57793r890544_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
