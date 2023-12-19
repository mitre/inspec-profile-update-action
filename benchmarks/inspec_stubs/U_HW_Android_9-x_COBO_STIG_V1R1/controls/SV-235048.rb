control 'SV-235048' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to not allow backup of [all applications, configuration data] to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud-based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review Honeywell Android device configuration settings to determine if the capability to back up to a locally connected system has been disabled. 

This validation procedure is performed on both the MDM Administration console and the Android Pie device. 

On the MDM console:
1. Open Device Restrictions.
2. Open Restrictions settings.
3. Ensure "Disallow usb file transfer" is selected.

On the Honeywell Android Pie device:
1. Plug USB cable into Android Pie device and connect to a non-DoD network-managed PC. 
2. Go to Settings >> Connected devices >> USB.
3. Ensure No data transfer is selected.

If the MDM console device policy is not set to disable the capability to back up to a locally connected system or on the Honeywell Android Pie device, the device policy is not set to disable the capability to back up to a locally connected system, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android device to disable backup to locally connected systems.

NOTE: On Restrictions, the backup features for Honeywell are not in the framework.

On the MDM console:
1. Open Device Restrictions.
2. Open Restrictions settings.
3. Select "Disallow usb file transfer".'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38236r623054_chk'
  tag severity: 'medium'
  tag gid: 'V-235048'
  tag rid: 'SV-235048r626530_rule'
  tag stig_id: 'HONW-09-003700'
  tag gtitle: 'PP-MDF-301220'
  tag fix_id: 'F-38199r623055_fix'
  tag 'documentable'
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
