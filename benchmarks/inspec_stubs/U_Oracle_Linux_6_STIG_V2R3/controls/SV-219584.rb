control 'SV-219584' do
  title 'The operating system must enforce requirements for the connection of mobile devices to operating systems.'
  desc 'USB storage devices such as thumb drives can be used to introduce unauthorized software and other vulnerabilities. Support for these devices should be disabled and the devices themselves should be tightly controlled.'
  desc 'check', 'If the system is configured to prevent the loading of the "usb-storage" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d | grep -i “/bin/true”

If no line is returned, this is a finding.'
  desc 'fix', 'To prevent USB storage devices from being used, configure the kernel module loading system to prevent automatic loading of the USB storage driver. To configure the system to prevent the "usb-storage" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install usb-storage /bin/true

This will prevent the "modprobe" program from loading the "usb-storage" module, but will not prevent an administrator (or another program) from using the "insmod" program to load the module manually.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21309r358292_chk'
  tag severity: 'medium'
  tag gid: 'V-219584'
  tag rid: 'SV-219584r603263_rule'
  tag stig_id: 'OL6-00-000503'
  tag gtitle: 'SRG-OS-000114'
  tag fix_id: 'F-21308r358293_fix'
  tag 'documentable'
  tag legacy: ['SV-64823', 'V-50617']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
