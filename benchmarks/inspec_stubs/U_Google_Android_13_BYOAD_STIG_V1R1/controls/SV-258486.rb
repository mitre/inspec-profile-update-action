control 'SV-258486' do
  title 'Google Android 13 must be configured to not allow backup of all work profile applications to remote systems.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the mobile operating system (MOS). Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DOD devices may synchronize DOD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review managed Google Android 13 device configuration settings to determine if the capability to back up to a remote system has been disabled.

Note: Since personal accounts cannot be added to the work profile (GOOG-13-710100), this control only impacts personal accounts, this setting is used to prevent violations within the work profile for backing up data. This is not applicable to the personal profile.

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 13 device. 

On the EMM console:

1. Open "Device owner management".
2. Verify "Enable backup service" is toggled to "OFF".

On the managed Google Android 13 device:

1. Go to Settings >> System >> System >> Backup.
2. Select "Work".
3. Verify Backup settings is "Not available".

If backup service for the work profile has not been disabled, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to disable backup to remote systems (including commercial clouds).

On the EMM console:

1. Open "Device owner management".
2. Toggle "Enable backup service" to "OFF".'
  impact 0.5
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62226r929272_chk'
  tag severity: 'medium'
  tag gid: 'V-258486'
  tag rid: 'SV-258486r929274_rule'
  tag stig_id: 'GOOG-13-708600'
  tag gtitle: 'PP-MDF-333250'
  tag fix_id: 'F-62135r929273_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
