control 'SV-258393' do
  title 'Google Android 14 must be configured to not allow backup of [all applications, configuration data] to remote systems.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the mobile operating system (MOS). Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DOD devices may synchronize DOD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review managed Google Android 14 device configuration settings to determine if the capability to back up to a remote system has been disabled. 

Note: Since personal accounts cannot be added to the work profile (GOOG-14-009800), this control only impacts personal profile accounts. Site can allow backup based on local policy.

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 14 device. 

On the EMM console:

COBO and COPE:

1. Open "Device owner management".
2. Verify "Enable backup service" is toggled to "OFF".

On the managed Google Android 14 device:

COBO:

1. Go to Settings >> System >> System >> Backup.
2. Verify Backup settings is "Not available".

COPE:

1. Go to Settings >> System >> System >> Backup.
2. Select "Work".
3. Verify Backup settings is "Not available".

If the EMM console device policy is not set to disable the capability to back up to a remote system or on the managed Google Android 14 device, the device policy is not set to disable the capability to back up to a remote system, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to disable backup to remote systems (including commercial clouds).

On the EMM console:

COBO and COPE:

1. Open "Device owner management".
2. Toggle "Enable backup service" to "OFF".

Note: Since personal accounts cannot be added to the work profile (GOOG-14-009800), this control only impacts personal profile accounts. Site can allow backup based on local policy.'
  impact 0.5
  ref 'DPMS Target Google Android 14 COBO'
  tag check_id: 'C-62134r928202_chk'
  tag severity: 'medium'
  tag gid: 'V-258393'
  tag rid: 'SV-258393r928204_rule'
  tag stig_id: 'GOOG-14-008600'
  tag gtitle: 'PP-MDF-333250'
  tag fix_id: 'F-62058r928203_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
