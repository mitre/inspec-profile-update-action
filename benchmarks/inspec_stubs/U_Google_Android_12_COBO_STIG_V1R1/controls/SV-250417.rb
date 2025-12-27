control 'SV-250417' do
  title 'Google Android 12 must be configured to disable all data signaling over [assignment: list of externally accessible hardware ports (for example, USB)].'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD sensitive information.

SFR ID: FMT_MOF_EXT.1.2 #24'
  desc 'check', 'Review the device configuration to confirm that the USB port is disabled except for charging the device.

On the EMM console:
1. Open "Set user restrictions"..
2. Verify that "Enable USB" is toggled to OFF.
 
If on EMM console the USB port is not disabled, this is a finding.'
  desc 'fix', 'Configure Google Android 12 device to disable the USB port (except for charging the device).

COPE and COBO:

On the EMM console:
1. Open "Set user restrictions"..
2. Toggle "Enable USB" to OFF.'
  impact 0.5
  ref 'DPMS Target Google Android 12 COBO'
  tag check_id: 'C-53852r796757_chk'
  tag severity: 'medium'
  tag gid: 'V-250417'
  tag rid: 'SV-250417r802782_rule'
  tag stig_id: 'GOOG-12-012200'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-53806r796758_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
