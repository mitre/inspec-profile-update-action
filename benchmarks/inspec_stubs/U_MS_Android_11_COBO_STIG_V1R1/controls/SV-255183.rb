control 'SV-255183' do
  title 'Microsoft Android 11 must be configured to not allow backup of all applications and configuration data to remote systems.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the Microsoft Android device. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DOD devices may synchronize DOD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the capability to back up to a remote system has been disabled. 

Note: Since personal accounts cannot be added to the work profile (MSFT-11-009200), this control only impacts personal profile accounts. Site can allow backup based on local policy.

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open User restrictions.
2. Verify that "Disallow backup service" is toggled to "Off".

On the Microsoft Android 11 device:
1. Go to Settings >> System.
2. Ensure Backup is set to "Off".

If the EMM console device policy is not set to disable the capability to back up to a remote system or on the Android 11 device, the device policy is not set to disable the capability to back up to a remote system, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to disable backup to remote systems (including commercial clouds).

Note: On a Restrictions, data in the work profile cannot be backed up by default.

On the EMM console:
1. Open "Set user restrictions".
2. Ensure "Enable backup service" is not selected.

Note: Since personal accounts cannot be added to the work profile (MSFT-11-009200), this control only impacts personal profile accounts. Site can allow backup based on local policy.'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58796r870683_chk'
  tag severity: 'medium'
  tag gid: 'V-255183'
  tag rid: 'SV-255183r870685_rule'
  tag stig_id: 'MSFT-11-003900'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-58740r870684_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
