control 'SV-205869' do
  title 'Windows Server 2019 Telemetry must be configured to Security or Basic.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "Security" option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender, and telemetry client settings. "Basic" sends basic diagnostic and usage data and may be required to support some Microsoft services.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\

Value Name: AllowTelemetry

Type: REG_DWORD
Value: 0x00000000 (0) (Security), 0x00000001 (1) (Basic)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Data Collection >> "Allow Telemetry" to "Enabled" with "0 - Security [Enterprise Only]" or "1 - Basic" selected in "Options".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6134r355969_chk'
  tag severity: 'medium'
  tag gid: 'V-205869'
  tag rid: 'SV-205869r921945_rule'
  tag stig_id: 'WN19-CC-000250'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6134r921944_fix'
  tag 'documentable'
  tag legacy: ['SV-103345', 'V-93257']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
