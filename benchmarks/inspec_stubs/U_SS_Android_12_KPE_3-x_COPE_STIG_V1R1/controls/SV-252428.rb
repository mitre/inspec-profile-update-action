control 'SV-252428' do
  title "Samsung Android's Work profile must be configured to not allow backup of [all applications, configuration data] to remote systems.

- Disable Data Sync Framework"
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the MOS. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Verify requirement KNOX-12-210220 (Disallow modify accounts) has been implemented.

If "Disallow modify accounts" has not been implemented, this is a finding.'
  desc 'fix', 'Implement "Disallow modify accounts" (see requirement KNOX-12-210220)'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COPE'
  tag check_id: 'C-55884r815495_chk'
  tag severity: 'medium'
  tag gid: 'V-252428'
  tag rid: 'SV-252428r815497_rule'
  tag stig_id: 'KNOX-12-210230'
  tag gtitle: 'PP-MDF-323250'
  tag fix_id: 'F-55834r815496_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
