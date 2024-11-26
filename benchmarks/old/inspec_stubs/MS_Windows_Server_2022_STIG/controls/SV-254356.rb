control 'SV-254356' do
  title 'Windows Server 2022 Diagnostic Data must be configured to send "required diagnostic data" or "optional diagnostic data".'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "send required diagnostic data" option for Allow Diagnostic Data configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender, and Diagnostic Data client settings. "Optional Diagnostic Data" sends basic diagnostic and usage data and may be required to support some Microsoft services.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\

Value Name: AllowTelemetry

Type: REG_DWORD
Value:  0x00000001 (1), 0x00000003 (3)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Data Collection and Preview Build >> Allow Diagnostic Data to "Enabled" with "Send required diagnostic data" selected or "Send optional diagnostic data".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57841r916219_chk'
  tag severity: 'medium'
  tag gid: 'V-254356'
  tag rid: 'SV-254356r916220_rule'
  tag stig_id: 'WN22-CC-000250'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57792r902887_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
