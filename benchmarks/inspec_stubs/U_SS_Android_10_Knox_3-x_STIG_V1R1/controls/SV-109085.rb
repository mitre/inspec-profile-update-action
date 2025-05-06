control 'SV-109085' do
  title 'Samsung Android must be configured to enforce a USB host mode exception list. Note: This configuration allows DeX mode (with input devices), which is DoD-approved for use.'
  desc 'The USB host mode feature allows USB devices to connect to the device (e.g., USB flash drives, USB mouse, USB keyboard) using a micro USB to USB adapter cable. The USB host mode exception list allows selected USB devices to operate, while disallowing others, based on their USB device class.

With some USB device classes, a user can copy sensitive DoD information to external USB storage unencrypted, resulting in compromise of DoD data. However, some USB device classes do not allow data to be copied, such as Human Interface Devices (HID).

Disabling all USB devices except for HID mitigates the risk of compromising sensitive DoD data.

This allows for DeX mode to be used, with a USB keyboard and mouse, without compromising DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android device configuration settings to determine if USB host mode exception list is configured, or alternatively, if USB host mode is disabled.

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

****

Method #1: Use USB exception list, which allows DeX usage (preferred).

On the management tool, in the device KPE restrictions section, verify that "HID" is the only USB class included in the "USB host mode exception list".

On the Samsung Android device, do the following:
1. Connect a micro USB-to-USB "On the Go" (OTG) adapter to the device.
2. Connect a USB thumb drive to the adapter.
3. Verify that the device cannot access the USB thumb drive.

If on the management tool the "USB host mode exception list" includes a USB class other than "HID", or on the Samsung Android device the USB thumb drive can be mounted, this is a finding.

****

Method #2: Disable USB host mode.

On the management tool, in the device KPE restrictions section, set "USB host mode" to "Disable".

On the Samsung Android device, do the following:
1. Connect a micro USB-to-USB "On the Go" (OTG) adapter to the device.
2. Connect a USB thumb drive to the adapter.
3. Verify that the device cannot access the USB thumb drive.

If on the management tool the "USB host mode" is not set to "Disable", or on the Samsung Android device the USB thumb drive can be mounted, this is a finding.'
  desc 'fix', 'Configure Samsung Android with a USB host mode exception list, or alternatively, disable the use of USB host mode.

Do one of the following:
- Method #1: Use USB exception list, which allows DeX usage (preferred).
- Method #2: Disable USB host mode.

****

Method #1: Use USB exception list, which allows DeX usage (preferred).

On the management tool, in the device KPE restrictions section, add the "HID" USB class to the "USB host mode exception list".

****

Method #2: Disable USB host mode.

On the management tool, in the device KPE restrictions section, set "USB host mode" to "Disable".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3.x'
  tag check_id: 'C-98831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99981'
  tag rid: 'SV-109085r1_rule'
  tag stig_id: 'KNOX-10-011200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-105665r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
