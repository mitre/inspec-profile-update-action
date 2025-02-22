control 'SV-91255' do
  title 'The Samsung Android 7 with Knox must be configured to not allow backup of [all applications, configuration data] to remote systems: Disable Allow Google Accounts Auto Sync.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the Samsung Android 7 with Knox. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD-sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'This requirement is Not Applicable if the AO has approved unmanaged personal space/container (COPE use case). The site must have an AO signed document showing the AO has assumed the risk for using an unmanaged personal container.

Review Samsung Android 7 with Knox configuration settings to determine if the capability to back up to a remote system has been disabled. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow Google Accounts Auto Sync" checkbox in the "Android Restrictions" rule. 
2. Verify the checkbox is not selected.
3. View the "application disable list".
4. Verify the list contains all preinstalled cloud backup applications.

On the Samsung Android 7 with Knox device, do the following:
1. Attempt to launch a cloud backup application located on the device.
2. Verify the application will not launch.

If the MDM console "Allow Google Accounts Auto Sync" checkbox is selected, or on the Samsung Android 7 with Knox device, the user can enable "Back up my data", this is a finding.

If the "Application disable list" configuration in the MDM console does not contain all pre-installed public cloud backup applications, or if the user is able to successfully launch an application on this list, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable backup to remote systems (including commercial clouds).

On the MDM console, do the following: 
- Deselect the "Allow Google Accounts Auto Sync" checkbox in the "Android Restrictions" rule.
- List all pre-installed public cloud backup applications, in the application disable list'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76225r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76559'
  tag rid: 'SV-91255r1_rule'
  tag stig_id: 'KNOX-07-004950'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-83253r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
