control 'SV-254797' do
  title 'Google Android 13 must be configured to disable all data signaling over [assignment: list of externally accessible hardware ports (for example, USB)].'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DOD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DOD sensitive information.

SFR ID: FMT_MOF_EXT.1.2 #24'
  desc 'check', 'Review the device configuration to confirm that the USB port is disabled except for charging the device.

On the EMM console:
1. Open "Set user restrictions".
2. Verify "Enable USB" is toggled to "OFF".
 
If on EMM console the USB port is not disabled, this is a finding.'
  desc 'fix', 'Configure Google Android 13 device to disable the USB port (except for charging the device).

COPE and COBO:

On the EMM console:
1. Open "Set user restrictions".
2. Toggle "Enable USB" to "OFF".'
  impact 0.5
  ref 'DPMS Target Google Android 13 COPE'
  tag check_id: 'C-58408r862771_chk'
  tag severity: 'medium'
  tag gid: 'V-254797'
  tag rid: 'SV-254797r862773_rule'
  tag stig_id: 'GOOG-13-012200'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58354r862772_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
