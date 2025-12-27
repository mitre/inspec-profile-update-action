control 'SV-255159' do
  title "Samsung Android's Work profile must be configured to not allow backup of all applications, configuration data to remote systems.

- Disable Data Sync Framework."
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the MOS. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DOD devices may synchronize DOD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. The Data Sync Framework allows apps to synchronize data between the mobile device and other web based services. This uses accounts for those services that the user has added to the mobile device. Preventing the user from adding accounts to the device mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Verify requirement KNOX-13-210230 (Disallow modify accounts) has been implemented.

If "Disallow modify accounts" has not been implemented, this is a finding.'
  desc 'fix', 'Implement "Disallow modify accounts" (see requirement KNOX-13-210230)'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COPE'
  tag check_id: 'C-58772r867412_chk'
  tag severity: 'medium'
  tag gid: 'V-255159'
  tag rid: 'SV-255159r867414_rule'
  tag stig_id: 'KNOX-13-210240'
  tag gtitle: 'PP-MDF-323250'
  tag fix_id: 'F-58716r867413_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
