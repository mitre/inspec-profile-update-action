control 'SV-221712' do
  title 'The Oracle Linux operating system must be configured to disable USB mass storage.'
  desc 'USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity.

'
  desc 'check', 'Verify the operating system disables the ability to load the USB Storage kernel module.

# grep -r usb-storage /etc/modprobe.d/* | grep -i "/bin/true" | grep -v "^#"

install usb-storage /bin/true

If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use USB mass storage devices.

Check to see if USB mass storage is disabled with the following command:

# grep usb-storage /etc/modprobe.d//* | grep -i "blacklist.conf" | grep -v "^#"
blacklist usb-storage

If the command does not return any output or the output is not "blacklist usb-storage", and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the USB Storage kernel module.

Create a file under "/etc/modprobe.d" with the following command:

# touch /etc/modprobe.d/usb-storage.conf

Add the following line to the created file:

install usb-storage /bin/true

Configure the operating system to disable the ability to use USB mass storage devices.

# vi /etc/modprobe.d/blacklist.conf

Add or update the line:

blacklist usb-storage'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36273r602413_chk'
  tag severity: 'medium'
  tag gid: 'V-221712'
  tag rid: 'SV-221712r603260_rule'
  tag stig_id: 'OL07-00-020100'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-36237r602414_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['V-99163', 'SV-108267']
  tag cci: ['CCI-000778', 'CCI-000366', 'CCI-001958']
  tag nist: ['IA-3', 'CM-6 b', 'IA-3']
end
