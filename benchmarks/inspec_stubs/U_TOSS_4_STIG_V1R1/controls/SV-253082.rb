control 'SV-253082' do
  title 'TOSS must be configured to disable USB mass storage.'
  desc 'USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity.

'
  desc 'check', 'Verify the operating system disables the ability to load the USB Storage kernel module.

$ sudo grep -r usb-storage /etc/modprobe.d/* | grep "install"

install usb-storage /bin/false

If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use USB mass storage devices.

Check to see if USB mass storage is disabled with the following command:

$ sudo grep -r usb-storage /etc/modprobe.d/* | grep "blacklist"

blacklist usb-storage

If the command does not return any output or the output is not "blacklist usb-storage", and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the USB Storage kernel module.

Create a file under "/etc/modprobe.d" with the following command:

$ sudo touch /etc/modprobe.d/usb-storage.conf

Add the following line to the created file:

install usb-storage /bin/true

Configure the operating system to disable the ability to use USB mass storage devices.

$ sudo vi /etc/modprobe.d/blacklist.conf

Add or update the line:

blacklist usb-storage'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56535r824916_chk'
  tag severity: 'medium'
  tag gid: 'V-253082'
  tag rid: 'SV-253082r824918_rule'
  tag stig_id: 'TOSS-04-040280'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-56485r824917_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163']
  tag 'documentable'
  tag cci: ['CCI-000778', 'CCI-001958']
  tag nist: ['IA-3', 'IA-3']
end
