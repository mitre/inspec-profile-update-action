control 'SV-84729' do
  title 'Windows 10 Mobile must not allow backup to remote systems and must have a mechanism to restrict abilities of applications and OS components that leverage cloud storage by blocking backup to OneDrive.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the MOS. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD-sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

For Windows 10 Mobile, this requirement is needed to prevent access to Cloud Services such as OneDrive by OS applications and components such as:

• OneNote
• Backup

SFR ID: FMT_SMF_EXT.1.1 #40"
  desc 'check', 'This guidance only needs to be done once as it is the same procedure used for MSWM-10-911107.

Review Windows 10 Mobile configuration settings to determine if the mobile device has its settings for remote backup disabled. If feasible, use a spare device to determine if enabling synching of settings is permitted.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.   

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for "allow settings synchronization".
3. Verify that setting restriction is turned off/disallowed.

On the Windows 10 Mobile device:

1. From the Start page, swipe to the left to show the App list.
2. Find and tap on "Settings".
3. In the Settings list, tap on "Update & security".
4. Tap on “Backup” on the "Update & security" page.
5. Verify the setting "Back up content from participating apps” is set to “Off” and disabled. 
6. Verify the setting "Back up settings like my Start screen layout, accounts, and passwords” is set to “Off” and disabled. 
7. Tap on the “More options” text at the bottom of the page.
8. Verify that under the title "Overview", a message is displayed that says "Backup is disabled" and the "Back up now" button is disabled and that under the title "Schedule backups", the toggle setting "Enable automatic backups” is set to “Off” and disabled. 

If the MDM does not have the "allow settings synchronization" policy disabled or, if the Windows 10 Mobile device is not configured with "Back up content from participating apps” set to “Off” and disabled, "Back up settings like my Start screen layout, accounts, and passwords” set to “Off” and disabled , "Back up now” button is set to “Off” and disabled , and “Enabled automatic backups” set to "Off" and disabled, this is a finding.'
  desc 'fix', 'Configure the MDM system to require the "allow settings synchronization" policy to be disabled for Windows 10 Mobile devices.

Deploy the MDM policy to managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70583r3_chk'
  tag severity: 'medium'
  tag gid: 'V-70107'
  tag rid: 'SV-84729r2_rule'
  tag stig_id: 'MSWM-10-202507'
  tag gtitle: 'PP-MDF-201018'
  tag fix_id: 'F-76343r2_fix'
  tag 'documentable'
  tag mitigations: 'MSWM-10-202507'
  tag mitigation_control: 'Currently in Windows 10 Mobile the resolution for this requirement to restrict OneDrive/Cloud access from a backend network control perspective.

In a new Windows 10 release coming in 2016 we will add restricting backup capability by extending the capability of the Experience/AllowSyncMySettings MDM policy.'
  tag cci: ['CCI-000366', 'CCI-002338']
  tag nist: ['CM-6 b', 'AC-20 (3)']
end
