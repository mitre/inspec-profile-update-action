control 'SV-241209' do
  title 'Samsung Android Work Environment must be configured to not allow backup of all applications, configuration data to remote systems (device management backup). - Disable Backup Services'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the MOS. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review Samsung Android configuration settings to determine if the capability to back up to a remote system has been disabled.

This requirement is inherently met for COPE because data in a "Profile/Workspace" cannot be backed up by default. 

This validation procedure is applicable to COBO only.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the Work Environment restrictions section, verify that "Backup service" is set to "Disallow".

On the Samsung Android device, do the following:
1. Open Settings >> Accounts and backup >> Backup and restore.
2. Verify that "Backup service not available" is listed.

If on the management tool "Backup service" is not set to "Disallow", or on the Samsung Android device "Backup service not available" is not listed, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to disable backup to remote systems (including commercial clouds) (device management backup).

This requirement is inherently met for COPE because data in a "Profile/Workspace" cannot be backed up by default. 

This guidance is applicable to COBO only.

On the management tool, in the Work Environment restrictions section, set "Backup service" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44485r680266_chk'
  tag severity: 'medium'
  tag gid: 'V-241209'
  tag rid: 'SV-241209r852769_rule'
  tag stig_id: 'KNOX-10-003800'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-44444r680267_fix'
  tag 'documentable'
  tag legacy: ['SV-109051', 'V-99947']
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
