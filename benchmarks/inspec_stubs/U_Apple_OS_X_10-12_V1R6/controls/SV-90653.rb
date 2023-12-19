control 'SV-90653' do
  title 'The OS X system must be configured with Bluetooth turned off unless approved by the organization.'
  desc 'The Bluetooth kernel extension must be disabled, as wireless access introduces unnecessary security risks. Disabling Bluetooth support with a configuration profile mitigates this risk.'
  desc 'check', 'If Bluetooth connectivity is required to facilitate use of approved external devices, this is not applicable.

To check if Bluetooth is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableBluetooth

If there is no result, or if "DisableBluetooth" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Bluetooth Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75649r1_chk'
  tag severity: 'low'
  tag gid: 'V-75965'
  tag rid: 'SV-90653r1_rule'
  tag stig_id: 'AOSX-12-000065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82603r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
