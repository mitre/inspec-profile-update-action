control 'SV-253394' do
  title 'Windows Update must not obtain updates from other PCs on the internet.'
  desc 'Windows 11 allows Windows Update to obtain updates from additional sources instead of Microsoft. In addition to Microsoft, updates can be obtained from and sent to PCs on the local network as well as on the Internet. This is part of the Windows Update trusted process, however to minimize outside exposure, obtaining updates from or sending to systems on the internet must be prevented.'
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

A value of 0x00000003 (3), Internet, is a finding.

Standalone systems (configured in Settings):
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config\\

Value Name: DODownloadMode

Value Type: REG_DWORD
Value: 0x00000000 (0) - Off
0x00000001 (1) - LAN'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Delivery Optimization >> "Download Mode" to "Enabled" with any option except "Internet" selected.

Acceptable selections include:
Bypass (100)
Group (2)
HTTP only (0)
LAN (1)
Simple (99)

.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56847r829264_chk'
  tag severity: 'low'
  tag gid: 'V-253394'
  tag rid: 'SV-253394r829266_rule'
  tag stig_id: 'WN11-CC-000206'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56797r829265_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
