control 'SV-241210' do
  title 'Samsung Android Work Environment must be configured to not allow backup of all applications, configuration data to remote systems (account management backup). - Disable Data Sync'
  desc 'SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review Samsung Android configuration settings to determine if the capability to back up to a remote system has been disabled. 

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

****

Method #1: AE Account management

On the management tool, in the Work Environment restrictions section, verify that "Account Management" is set to "Disable" for Samsung accounts, Google accounts, and each AO-approved app that uses accounts for data backup/sync.

For COPE: On the Samsung Android device, do the following:
1. Open Settings >> Work profile >> Accounts.
2. Verify that accounts are grayed out, or an account cannot be added.

For COBO: On the Samsung Android device, do the following:
1. Open Settings >> Accounts and backup >> Accounts.
2. Verify that accounts are grayed out, or an account cannot be added.

If on the management tool "Account Management" is not set to "Disable" for Samsung accounts, Google accounts, and each AO-approved app that uses accounts for data backup/sync, or on the Samsung Android device an account can be added, this is a finding.

****

Method #2: KPE Account Addition Blacklist

On the management tool, do the following:
1. In the Work Environment KPE Account section, verify that "Account Addition Blacklist" is set to "Blacklist all" for: Samsung accounts and Google accounts.
2. In the Work Environment, verify that no App that uses accounts for data backup/sync is approved.

For COPE: On the Samsung Android device, do the following:
1. Open Settings >> Work profile >> Accounts
2. Verify that is accounts are grayed out, or an account cannot be added.

For COBO: On the Samsung Android device, do the following:
1. Open Settings >> Accounts and backup >> Accounts
2. Verify that is accounts are grayed out, or an account cannot be added.

If on the management tool "Account Addition Blacklist" is not set to "Blacklist all" for Samsung accounts and Google accounts, or on the Samsung Android device an account can be added, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to disable backup to remote systems (including commercial clouds) (account management backup).

Do one of the following:
- Method #1: AE Account management
- Method #2: KPE Account Addition Blacklist

****

Method #1: AE Account management

On the management tool, in the Work Environment restrictions section, set "Account Management" to "Disable" for Samsung accounts, Google accounts, and each AO-approved app that uses accounts for data backup/sync.

****

Method #2: KPE Account Addition Blacklist

On the management tool, do the following:
1. in the Work Environment KPE Account section, set "Account Addition Blacklist" to "Blacklist all" for Samsung accounts and Google accounts.
2. In the Work Environment, do not approve any app that uses accounts for data backup/sync.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44486r680269_chk'
  tag severity: 'medium'
  tag gid: 'V-241210'
  tag rid: 'SV-241210r852770_rule'
  tag stig_id: 'KNOX-10-003900'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-44445r680270_fix'
  tag 'documentable'
  tag legacy: ['SV-109053', 'V-99949']
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
