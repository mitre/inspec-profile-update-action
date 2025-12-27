control 'SV-218087' do
  title 'The operating system must enforce requirements for the connection of mobile devices to operating systems.'
  desc 'USB storage devices such as thumb drives can be used to introduce unauthorized software and other vulnerabilities. Support for these devices should be disabled and the devices themselves should be tightly controlled.'
  desc 'check', 'If the system is configured to prevent the loading of the "usb-storage" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d | grep -i “/bin/true” | grep -v “#”

If no line is returned, this is a finding.'
  desc 'fix', 'To prevent USB storage devices from being used, configure the kernel module loading system to prevent automatic loading of the USB storage driver. To configure the system to prevent the "usb-storage" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install usb-storage /bin/true

This will prevent the "modprobe" program from loading the "usb-storage" module, but will not prevent an administrator (or another program) from using the "insmod" program to load the module manually.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19568r462418_chk'
  tag severity: 'medium'
  tag gid: 'V-218087'
  tag rid: 'SV-218087r603264_rule'
  tag stig_id: 'RHEL-06-000503'
  tag gtitle: 'SRG-OS-000114'
  tag fix_id: 'F-19566r462419_fix'
  tag 'documentable'
  tag legacy: ['SV-50291', 'V-38490']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
