control 'SV-252864' do
  title 'Zebra Android 11 must be configured to not allow backup of [all applications, configuration data] to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud-based), many if not all of these mechanisms are no longer present. This leaves backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review Zebra Android device configuration settings to determine if the capability to back up to a locally connected system has been disabled. 

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM console, do the following:
1. Open "Device owner management" section.
2. Verify that "Enable backup service" is toggled to "Off".
3. Open "User restrictions on parent".
4. Verify that "Disallow USB file transfer" is toggled to "On".

On the Android 11 device, do the following:
1. Plug a USB cable into Android 11 device and connect to a non-DoD network-managed PC. 
2. Go to Settings >> Connected devices >> USB.
3. Ensure “No data transfer” is selected.

If the EMM console device policy is not set to disable the capability to back up to a locally connected system or on the Android 11 device, the device policy is not set to disable the capability to back up to a locally connected system, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 11 device to disable backup to locally connected systems.

Note: On Restrictions, the backup features for Zebra are not in the framework.

On the EMM console:
1. Open "Device owner management" section.
2. Toggle "Enable backup service" to "Off".
3. Open "User restrictions on parent".
4. Select "Disallow USB file transfer".'
  impact 0.5
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56320r820517_chk'
  tag severity: 'medium'
  tag gid: 'V-252864'
  tag rid: 'SV-252864r820519_rule'
  tag stig_id: 'ZEBR-11-003700'
  tag gtitle: 'PP-MDF-301220'
  tag fix_id: 'F-56270r820518_fix'
  tag 'documentable'
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
