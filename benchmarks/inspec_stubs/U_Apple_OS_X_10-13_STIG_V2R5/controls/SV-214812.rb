control 'SV-214812' do
  title 'The macOS system must be configured with Bluetooth turned off unless approved by the organization.'
  desc 'The Bluetooth kernel extension must be disabled, as wireless access introduces unnecessary security risks. Disabling Bluetooth support with a configuration profile mitigates this risk.'
  desc 'check', 'If Bluetooth connectivity is required to facilitate use of approved external devices, this is not applicable.

To check if Bluetooth is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableBluetooth

If the return is null or is not "DisableBluetooth = 1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Bluetooth Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16012r397008_chk'
  tag severity: 'low'
  tag gid: 'V-214812'
  tag rid: 'SV-214812r609363_rule'
  tag stig_id: 'AOSX-13-000065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16010r397009_fix'
  tag 'documentable'
  tag legacy: ['V-81483', 'SV-96197']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
