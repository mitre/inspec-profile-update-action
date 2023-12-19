control 'SV-88215' do
  title 'Windows Telemetry must be configured to Security or Basic.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "Security" option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender, and telemetry client settings. "Basic" sends basic diagnostic and usage data and may be required to support some Microsoft services.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\

Value Name: AllowTelemetry

Type: REG_DWORD
Value: 0x00000000 (0) (Security), 0x00000001 (1) (Basic)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Data Collection and Preview Builds>> "Allow Telemetry" to "Enabled" with "0 - Security [Enterprise Only]" or "1 - Basic" selected in "Options".'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73633r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73551'
  tag rid: 'SV-88215r1_rule'
  tag stig_id: 'WN16-CC-000290'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-80001r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
