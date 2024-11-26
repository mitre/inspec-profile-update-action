control 'SV-84761' do
  title 'Windows 10 Mobile must be configured to implement the management setting: 

Disable the capability for synching settings such as the theme, application settings, Internet Explorer sites visited, and cached passwords to Microsoft OneDrive cloud storage.'
  desc "Backups to remote systems (including cloud backup) can leave data vulnerable to breach on the external systems, which often offer less protection than the MOS. Where the remote backup involves a cloud-based solution, the backup capability is often used to synchronize data across multiple devices. In this case, DoD devices may synchronize DoD-sensitive information to a user's personal device or other unauthorized computers that are vulnerable to breach. Disallowing remote backup mitigates this risk.

For Windows 10 Mobile, this requirement is needed to prevent access to Cloud Services such as OneDrive by OS applications and components such as:

• Backup

SFR ID: FMT_SMF_EXT.1.1 #45"
  desc 'check', 'This guidance only needs to be done once as it is the same procedure used for MSWM-10-202507.

Review Windows 10 Mobile configuration settings to determine if the mobile device has the ability to sync its settings to remote backup disabled. If feasible, use a spare device to determine if enabling synching of settings is permitted.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.   

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for "allow settings synchronization".
3. Verify that setting restriction is turned off/disallowed.
On the Windows 10 Mobile device:

1. Launch "Settings".
2. Navigate to "Accounts" and then tap on "Sync your settings".
3. Verify that all of the "Sync settings", "Theme", and "Passwords" toggle settings are set to "Off" and they cannot be changed.

If the MDM does not have the "allow settings synchronization" policy disabled or if on the device any of the "Sync settings", "Theme", and "Passwords" toggle settings are not set to "Off" or they can be changed, this is a finding.'
  desc 'fix', 'Configure the MDM system to require the "allow settings synchronization" policy to be disabled for Windows 10 Mobile devices.

Deploy the MDM policy to managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70615r3_chk'
  tag severity: 'medium'
  tag gid: 'V-70139'
  tag rid: 'SV-84761r2_rule'
  tag stig_id: 'MSWM-10-911107'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76375r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
