control 'SV-258700' do
  title 'The Samsung Android device must be configured to disable all data signaling over [assignment: list of externally accessible hardware ports (for example, USB)].'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DOD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DOD sensitive information.

SFR ID: FMT_MOF_EXT.1.2 #24'
  desc 'check', 'Review the device configuration to confirm the USB port is disabled except for charging the device.

On the management tool:
Verify "Enable USB data signaling" is toggled to "OFF".
 
If on the management tool the USB port is not disabled, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 14 device to disable the USB port (except for charging the device).

On the management tool:
Toggle "Enable USB data signaling" to "OFF".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62440r931298_chk'
  tag severity: 'medium'
  tag gid: 'V-258700'
  tag rid: 'SV-258700r931300_rule'
  tag stig_id: 'KNOX-14-225080'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62349r931299_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
