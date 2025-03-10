control 'SV-248837' do
  title 'OL 8 must be configured to disable the ability to use USB mass storage devices.'
  desc 'USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity.'
  desc 'check', 'Verify the operating system disables the ability to load the USB Storage kernel module.

$ sudo grep -r usb-storage /etc/modprobe.d/* | grep -i "/bin/true"

install usb-storage /bin/true

If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Determine if USB mass storage is disabled with the following command: 
 
$ sudo grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#" 

/etc/modprobe.d/blacklist.conf:blacklist usb-storage 
 
If the command does not return any output or the output is not "blacklist usb-storage" and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable the ability to use the USB Storage kernel module and to use USB mass storage devices.

$ sudo vi /etc/modprobe.d/blacklist.conf

Add or update the lines: 

install usb-storage /bin/true
blacklist usb-storage

Reboot the system for the settings to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52271r818695_chk'
  tag severity: 'medium'
  tag gid: 'V-248837'
  tag rid: 'SV-248837r818697_rule'
  tag stig_id: 'OL08-00-040080'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-52225r818696_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
