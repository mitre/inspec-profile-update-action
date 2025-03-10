control 'SV-217727' do
  title 'Samsung Android must be configured to not allow backup of [all applications, configuration data] to remote systems.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the mobile operating system. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review device configuration settings to confirm that backup to a remote system has been disabled. 

This procedure is performed on the MDM Administration console and the Samsung device. 

On the MDM console, for the device, do the following: 
1. In the "Knox restrictions" group, verify that "allow google backup" is not selected. 
2. In the "Knox restrictions" group, verify that "allow google accounts auto sync" is not selected. 
3. In the "Knox application" group, verify that the system application disable list contains all preinstalled cloud backup system apps. 

On the Samsung Android device: 
1. Open Settings. 
2. Tap "Accounts and backup". 
3. Tap "Backup and restore". 
4. Verify that "Backup my data" is disabled and cannot be enabled. 
5. Tap back and tap "Accounts". 
6. Tap a listed Google account. 
7. Tap "Sync account" and verify that all sync options are disabled and cannot be enabled. 
8. Review the apps on the "Personal" App screen and confirm that none of the cloud backup system apps are present. 

If on the MDM console "allow google backup" is selected or "allow google accounts auto sync" is selected, or on the Samsung Android device "Backup my data" can be enabled, "sync options" are enabled for a Google Account, or a "cloud backup" system app is present on the "Personal" App screen, this is a finding.'
  desc 'fix', 'Configure the Samsung Android to disable backup to remote systems (including commercial clouds). 

On the MDM console, for the device, do the following: 
1. In the "Knox restrictions" group, unselect "allow google backup". 
2. In the "Knox restrictions" group, unselect "allow google accounts auto sync". 
3. In the "Knox application" group, add all preinstalled public cloud backup system apps to the system application disable list if not already configured. 

Note: The guidance for disablement of system apps that have the characteristic "back up MD data to non-DoD cloud servers (including user and application access to cloud backup services)" is covered by KNOX-09-000105.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE Legacy'
  tag check_id: 'C-18945r362329_chk'
  tag severity: 'medium'
  tag gid: 'V-217727'
  tag rid: 'SV-217727r617478_rule'
  tag stig_id: 'KNOX-09-000865'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-18943r362330_fix'
  tag 'documentable'
  tag legacy: ['SV-103701', 'V-93615']
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
