control 'SV-242520' do
  title 'Zebra Android 10 must be configured to not allow backup of all applications and configuration data to remote systems.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the Zebra Android 10 device. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review Zebra Android 10 device configuration settings to determine if the capability to back up to a remote system has been disabled. 

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console:
1. Open User restrictions.
2. Verify "Disallow backup servicer" is not selected.

On the Zebra Android 10 device:
1. Go to Settings >> System.
2. Select "Backup".
3. Verify Backup is disabled for each profile listed.

If the MDM console device policy is not set to disable the capability to back up to a remote system or on the Android 10 device, the device policy is not set to disable the capability to back up to a remote system, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to disable backup to remote systems (including commercial clouds).

Note: On Restrictions, data in the work profile cannot be backed up by default.

On the MDM console:
1. Open User restrictions.
2. Ensure "Enable backup service" is not selected.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45795r714403_chk'
  tag severity: 'medium'
  tag gid: 'V-242520'
  tag rid: 'SV-242520r714405_rule'
  tag stig_id: 'ZEBR-10-003900'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-45752r714404_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
