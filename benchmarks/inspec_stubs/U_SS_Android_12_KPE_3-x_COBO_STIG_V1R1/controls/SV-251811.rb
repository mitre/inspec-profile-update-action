control 'SV-251811' do
  title 'Samsung Android must be configured to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor, including trust agents.'
  desc 'Trust agents allow a user to unlock a mobile device without entering a passcode when the mobile device is, for example, connected to a user-selected Bluetooth device or in a user-selected location. This technology would allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, this risk is mitigated - as users are forced to use passcodes that meet DoD passcode requirements

SFR ID: FMT_SMF_EXT.1.1 #22, FIA_UAU.5.1'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disabling Trust Agents.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify that "Trust Agents" are set to "Disable".

On the Samsung Android device: 
1. Open Settings >> Biometrics and security >> Other security settings >> Trust agents.
2. Verify that all listed Trust Agents are disabled and cannot be enabled.

If on the management tool "Trust Agents" are not set to "Disable", or on the Samsung Android device a "Trust Agent" can be enabled, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable Trust Agents.

On the management tool, in the device restrictions, set "Trust Agents" to "Disable".'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55271r814187_chk'
  tag severity: 'medium'
  tag gid: 'V-251811'
  tag rid: 'SV-251811r814189_rule'
  tag stig_id: 'KNOX-12-110090'
  tag gtitle: 'PP-MDF-323110'
  tag fix_id: 'F-55225r814188_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
