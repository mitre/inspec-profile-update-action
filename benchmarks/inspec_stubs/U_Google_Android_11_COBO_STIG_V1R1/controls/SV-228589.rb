control 'SV-228589' do
  title 'Google Android 11 must be configured to not allow backup of all applications and configuration data to remote systems.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the Google Android device. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review Google Android device configuration settings to determine if the capability to back up to a remote system has been disabled. 

NOTE: Since personal accounts cannot be added to the work profile (GOOG-11-009200), this control only impacts personal profile accounts. Site can allow backup based on local policy.

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM console, do the following:
1. Open User restrictions.
2. Verify that "Disallow backup service" is toggled to Off.

On the Android 11 device, do the following:
1. Go to Settings >> System.
2. Ensure Backup is set to "Off".

If the EMM console device policy is not set to disable the capability to back up to a remote system or on the Android 11 device, the device policy is not set to disable the capability to back up to a remote system, this is a finding.'
  desc 'fix', 'Configure the Google Android 11 device to disable backup to remote systems (including commercial clouds).

NOTE: On a Restrictions, data in the work profile cannot be backed up by default.

On the EMM console:
1. Open "Set user restrictions".
2. Ensure "Enable backup service" is not selected.

NOTE: Since personal accounts cannot be added to the work profile (GOOG-11-009200), this control only impacts personal profile accounts. Site can allow backup based on local policy.'
  impact 0.5
  ref 'DPMS Target Google Android 11 COBO'
  tag check_id: 'C-30824r505592_chk'
  tag severity: 'medium'
  tag gid: 'V-228589'
  tag rid: 'SV-228589r510289_rule'
  tag stig_id: 'GOOG-11-003900'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-30801r505593_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
