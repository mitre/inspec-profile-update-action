control 'SV-103991' do
  title 'Samsung Android Workspace must be configured to not allow backup of [all applications, configuration data] to remote systems.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the mobile operating system. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'Review the Samsung Android Workspace configuration settings to confirm that backup to a remote system (including commercial clouds) has been disabled.

This procedure is performed on the MDM Administration console and the Samsung Android device. 

On the MDM console, for the Workspace, do the following: 
1. In the "Knox restrictions" group, verify that "allow google accounts auto sync" is not selected. 
2. In the "Knox application" group, verify that the system application disable list contains all preinstalled cloud backup system apps. 

On the Samsung Android device: 
1. Open Settings. 
2. Tap "Workspace". 
3. Tap "Accounts". 
4. Tap a listed Google account. 
5. Tap "Sync account" and verify that all sync options are disabled and cannot be enabled. 
6. Review the apps on the "Workspace" App screen and confirm that none of the cloud backup system apps are present. 

If on the MDM console "allow google accounts auto sync" is selected, or on the Samsung Android device "sync options" are enabled for a Google Account, or a "cloud backup" system app is present on the "Workspace" App Screen, this is a finding.'
  desc 'fix', 'Configure the Samsung Android Workspace to disable backup to remote systems (including commercial clouds). 

On the MDM console, for the Workspace, do the following: 
1. In the "Knox restrictions" group, unselect "allow google accounts auto sync". 
2. In the "Knox application" group, add all preinstalled public cloud backup system apps to the system application disable list if not already configured. 

Note: The guidance for disablement of system apps that have the characteristic "back up MD data to non-DoD cloud servers (including user and application access to cloud backup services)" is covered by KNOX-09-000125.'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(Legacy)'
  tag check_id: 'C-93223r2_chk'
  tag severity: 'medium'
  tag gid: 'V-93905'
  tag rid: 'SV-103991r1_rule'
  tag stig_id: 'KNOX-09-000875'
  tag gtitle: 'PP-MDF-301230'
  tag fix_id: 'F-100153r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
