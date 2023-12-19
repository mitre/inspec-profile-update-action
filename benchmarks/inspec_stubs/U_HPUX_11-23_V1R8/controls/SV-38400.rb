control 'SV-38400' do
  title 'The system must have USB disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', '# ioscan -fnC usb

If the system uses USB, this is not applicable. By default, HP-UX systems tend to use both a USB keyboard and mouse. The following sample is a section of a system ioscan output showing the discovered USB controllers and devices. Notice, there are 3 NEC USB controllers. The first 2 USB controllers are OHCI (Open Host Controller Interface) controllers for low and full speed USB 1.0 and 1.1 devices. The 3rd USB controller is an EHCI (Enhanced Host Controller Interface) controller for high speed USB 2.0 devices. The first OHCI USB controller has a keyboard, a mouse, and a mass storage device attached. The second OHCI USB controller has no devices attached. The third USB controller, EHCI, has 2 mass storage devices attached.

Class       I H/W Path       Driver             S/W State       H/W Type       Description
================================================================================================
Usb 0 0/0/2/0       hcd             CLAIMED             INTERFACE             NEC OHCI Controller
usbcomp       0 0/0/2/0.1       usbcomposite       CLAIMED             DEVICE             USB Composite Device
usbhid       0 0/0/2/0.1.0       hid             CLAIMED             DEVICE             USB HID Kbd(0)
usbhid       1 0/0/2/0.1.1       hid             CLAIMED             DEVICE             USB HID Pointer(1)
usbms       0 0/0/2/0.1.2       ms             CLAIMED             DEVICE             USB Mass Storage [0]
usb       1 0/0/2/1       hcd             CLAIMED             INTERFACE       NEC OHCI Controller
usb       2 0/0/2/2       ehci             CLAIMED             INTERFACE       NEC EHCI Controller
usbms       2 0/0/2/2.2       ms             CLAIMED             DEVICE             USB Mass Storage [1]
usbms       3 0/0/2/2.3       ms             CLAIMED             DEVICE             USB Mass Storage [2]


Determine if the system has USB enabled. If it does, this is a finding.'
  desc 'fix', 'Disable USB on the system. In doing so, remember the keyboard and mouse will no longer work.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36789r1_chk'
  tag severity: 'low'
  tag gid: 'V-22578'
  tag rid: 'SV-38400r1_rule'
  tag stig_id: 'GEN008460'
  tag gtitle: 'GEN008460'
  tag fix_id: 'F-32168r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
