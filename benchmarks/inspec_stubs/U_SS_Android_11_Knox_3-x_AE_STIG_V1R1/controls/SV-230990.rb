control 'SV-230990' do
  title 'Samsung Android Work Environment must be configured to not allow backup of all applications, configuration data to remote systems (account management backup).

- Disable Data Sync'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the MOS. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review Samsung Android configuration settings to determine if the capability to back up to a remote system has been disabled. 

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the Work Environment restrictions section, verify that "Account Management" is set to "Disable" for Samsung accounts, Google accounts, and each AO-approved app that uses accounts for data backup/sync.

For COPE: On the Samsung Android device: 
1. Open Settings >> Work profile >> Accounts.
2. Verify that accounts are grayed out, or an account cannot be added.

For COBO: On the Samsung Android device: 
1. Open Settings >> Accounts and backup >> Managed accounts.
2. Verify that accounts are grayed out, or an account cannot be added.

If on the management tool "Account Management" is not set to "Disable" for Samsung accounts, Google accounts, and each AO-approved app that uses accounts for data backup/sync, or on the Samsung Android device an account can be added, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to disable backup to remote systems (including commercial clouds) (account management backup).

On the management tool, in the Work Environment restrictions section, set "Account Management" to "Disable" for Samsung accounts, Google accounts, and each AO-approved app that uses accounts for data backup/sync.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33920r592462_chk'
  tag severity: 'medium'
  tag gid: 'V-230990'
  tag rid: 'SV-230990r607691_rule'
  tag stig_id: 'KNOX-11-007500'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-33893r592463_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
