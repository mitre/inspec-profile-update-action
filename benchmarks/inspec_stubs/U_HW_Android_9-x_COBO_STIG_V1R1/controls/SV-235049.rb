control 'SV-235049' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to not allow backup of all applications and configuration data to remote systems.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the Honeywell Android device. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review Honeywell Android device configuration settings to determine if the capability to back up to a remote system has been disabled. 

This validation procedure is performed on both the MDM Administration console and the Android Pie device. 

On the MDM console:
1. Open Device Restrictions.
2. Open Restrictions settings.
3. Ensure "Disallow backup servicer" is not selected.

On the Honeywell Android Pie device:
1. Go to Settings >> System.
2. Ensure Backup is set to "Off".

If the MDM console device policy is not set to disable the capability to back up to a remote system or on the Honeywell Android Pie device, the device policy is not set to disable the capability to back up to a remote system, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android device to disable backup to remote systems (including commercial clouds).

NOTE: On Restrictions, data in the work profile cannot be backed up by default.

On the MDM console:
1. Open Device Restrictions.
2. Open Restrictions settings.
3. Ensure "Enable backup service" is not selected.'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38237r623057_chk'
  tag severity: 'medium'
  tag gid: 'V-235049'
  tag rid: 'SV-235049r626530_rule'
  tag stig_id: 'HONW-09-003900'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-38200r623058_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
