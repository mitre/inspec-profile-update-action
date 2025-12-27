control 'SV-228293' do
  title 'The Google Android Pie must be configured to not allow backup of all applications and configuration data to remote systems.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the Google Android device. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review Google Android device configuration settings to determine if the capability to back up to a remote system has been disabled. 

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console, do the following:

1. Open Device Restrictions.
2. Open Restrictions Settings.
3. Ensure "Disallow backup servicer" is not selected.

On the Android Pie device, do the following:

1. Go to Settings >> System.
2. Ensure Backup is set to "Off".

If the MDM console device policy is not set to disable the capability to back up to a remote system or on the Android Pie device, the device policy is not set to disable the capability to back up to a remote system, this is a finding.'
  desc 'fix', 'Configure the Google Android device to disable backup to remote systems (including commercial clouds).

NOTE: On a Restrictions, data in the work profile cannot be backed up by default.

On the MDM console:

1. Open Device Restrictions.
2. Open Restrictions Settings.
3. Ensure "Enable backup service" is not selected.'
  impact 0.5
  ref 'DPMS Target Google Android 9-x'
  tag check_id: 'C-30526r494946_chk'
  tag severity: 'medium'
  tag gid: 'V-228293'
  tag rid: 'SV-228293r852696_rule'
  tag stig_id: 'GOOG-09-003900'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-30511r494947_fix'
  tag 'documentable'
  tag legacy: ['SV-106439', 'V-97335']
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
