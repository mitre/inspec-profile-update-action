control 'SV-255116' do
  title 'Samsung Android must be configured to not allow backup of all applications and configuration data to remote systems.

- Disable Backup Services.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the MOS. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DOD devices may synchronize DOD sensitive information to a user's personal device or other unauthorized computers vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disabling backup to remote systems (including commercial clouds).

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions section, verify that "Backup service" is set to "Disable".

On the Samsung Android device:
1. Open Settings >> Accounts and backup.
2. Verify that any backup service listed cannot be configured to back up data.

If on the management tool "Backup service" is not set to "Disable", or on the Samsung Android device a listed backup service can be configured to back up data, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable backup to remote systems (including commercial clouds).

On the management tool, in the device restrictions, set "Backup service" to "Disable".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COBO'
  tag check_id: 'C-58729r867283_chk'
  tag severity: 'medium'
  tag gid: 'V-255116'
  tag rid: 'SV-255116r867285_rule'
  tag stig_id: 'KNOX-13-110100'
  tag gtitle: 'PP-MDF-323250'
  tag fix_id: 'F-58673r867284_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
