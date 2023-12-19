control 'SV-91253' do
  title 'The Samsung Android 7 with Knox must be configured to not allow backup of [all applications, configuration data] to remote systems: Deselect Allow Google Backup.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the Samsung Android 7 with Knox. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD-sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk. Google Backup is a device wide control and, if enabled, will backup both personal and Knox data to personal Google cloud storage accounts.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review Samsung Android 7 with Knox configuration settings to determine if the capability to back up to a remote system has been disabled. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow Google Backup" checkbox in the "Android Restrictions" rule. 
2. Verify the checkbox is not selected.

On the Samsung Android 7 with Knox device, do the following:
1. Open the device settings.
2. Select "Backup and reset" under the Google account section.
3. Verify "Back up my data" is disabled and cannot be enabled.

If the MDM console "Allow Google Backup" checkbox is selected, or on the Samsung Android 7 with Knox device, the user can enable "Back up my data", this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable backup to remote systems (including commercial clouds).

On the MDM console, do the following: Deselect the "Allow Google Backup" checkbox in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76217r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76557'
  tag rid: 'SV-91253r1_rule'
  tag stig_id: 'KNOX-07-004900'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-83239r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
