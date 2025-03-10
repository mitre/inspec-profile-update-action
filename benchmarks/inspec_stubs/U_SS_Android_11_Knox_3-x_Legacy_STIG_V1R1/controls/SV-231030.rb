control 'SV-231030' do
  title 'Samsung Android Work Environment must be configured to not allow backup of all applications, configuration data to remote systems (account management backup).

- Disable Data Sync'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the MOS. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review Samsung Android configuration settings to determine if the capability to back up to a remote system has been disabled. 

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool:
1. In the Work Environment Account section, verify that "Account Addition Denylist" is set to "Denylist all" for Samsung accounts and Google accounts.
2. In the Work Environment, verify that no app that uses accounts for data backup/sync is approved.

For COPE: On the Samsung Android device: 
1. Open Settings >> Work profile >> Accounts.
2. Verify that accounts are grayed out, or an account cannot be added.

For COBO: On the Samsung Android device: 
1. Open Settings >> Accounts and backup >> Manage accounts
2. Verify that accounts are grayed out, or an account cannot be added.

If on the management tool "Account Addition Denylist" is not set to "Denylist all" for Samsung accounts and Google accounts, or on the Samsung Android device an account can be added, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to disable backup to remote systems (including commercial clouds) (account management backup).

On the management tool:
1. In the Work Environment Account section, set "Account Addition Denylist" to "Denylist all" for Samsung accounts and Google accounts.
2. In the Work Environment, do not approve any app that uses accounts for data backup/sync.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33960r592704_chk'
  tag severity: 'medium'
  tag gid: 'V-231030'
  tag rid: 'SV-231030r608683_rule'
  tag stig_id: 'KNOX-11-007600'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-33933r592705_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
