control 'SV-38401' do
  title 'The system must have USB Mass Storage disabled unless needed.'
  desc 'USB is a common computer peripheral interface.  USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'On HP-UX systems with USB ports, the kernel module "usbd" is installed with the operating system. The "usbd" module enables and currently supports the use of a keyboard, a mouse and an optical drive. 
# /stand/system | grep -i usb
# ioscan -fnC usb

Ask the SA if the system requires USB mass storage. If the system requires the use of USB mass storage, this is not applicable.

If the kernel module "usbd" is installed and the system does not require usb mass storage, this is a finding.'
  desc 'fix', %q(If usb mass storage is not required and the system does not use the system's usb interface for keyboard/mouse input, remove the "usbd" module from the kernel, remake the kernel and reboot the system. Document the change(s).
# smh)
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36790r2_chk'
  tag severity: 'low'
  tag gid: 'V-22579'
  tag rid: 'SV-38401r1_rule'
  tag stig_id: 'GEN008480'
  tag gtitle: 'GEN008480'
  tag fix_id: 'F-32169r2_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
