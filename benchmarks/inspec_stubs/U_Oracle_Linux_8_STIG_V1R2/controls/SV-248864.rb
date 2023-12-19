control 'SV-248864' do
  title 'OL 8 must enable the USBGuard.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. 
 
Peripherals include but are not limited to such devices as flash drives, external storage, and printers. 
 
A new feature that OL 8 provides is the USBGuard software framework. The USBguard-daemon is the main component of the USBGuard software framework. It runs as a service in the background and enforces the USB device authorization policy for all USB devices. The policy is defined by a set of rules using a rule language described in the "usbguard-rules.conf" file. The policy and the authorization state of USB devices can be modified during runtime using the "usbguard" tool. 
 
The System Administrator (SA) must work with the site Information System Security Officer (ISSO) to determine a list of authorized peripherals and establish rules within the USBGuard software framework to allow only authorized devices.'
  desc 'check', 'Verify the operating system has enabled the use of the USBGuard with the following command:

$ sudo systemctl status usbguard.service

usbguard.service - USBGuard daemon
Loaded: loaded (/usr/lib/systemd/system/usbguard.service; enabled; vendor preset: disabled)
Active: active (running)

If the usbguard.service is not enabled and active, ask the SA to indicate how unauthorized peripherals are being blocked.

If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding.'
  desc 'fix', 'Configure the operating system to enable the blocking of unauthorized peripherals with the following commands:

$ sudo systemctl enable usbguard.service

$ sudo systemctl start usbguard.service

Note: Enabling and starting usbguard without properly configuring it for an individual system will immediately prevent any access over a usb device such as a keyboard or mouse.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52298r780156_chk'
  tag severity: 'medium'
  tag gid: 'V-248864'
  tag rid: 'SV-248864r780158_rule'
  tag stig_id: 'OL08-00-040141'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-52252r780157_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
