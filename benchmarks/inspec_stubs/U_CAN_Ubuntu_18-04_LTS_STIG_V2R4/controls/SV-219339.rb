control 'SV-219339' do
  title 'The Ubuntu operating system must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', 'Verify that Ubuntu operating system disables ability to load the USB storage kernel module.

# grep usb-storage /etc/modprobe.d/* | grep "/bin/true" 

install usb-storage /bin/true

If the command does not return any output, or the line is commented out, this is a finding.

Verify the operating system disables the ability to use USB mass storage device.

# grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"

blacklist usb-storage

If the command does not return any output, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to disable using the USB storage kernel module. 

Create a file under "/etc/modprobe.d" to contain the following:

# sudo su -c "echo install usb-storage /bin/true >> /etc/modprobe.d/DISASTIG.conf"

Configure the operating system to disable the ability to use USB mass storage devices.

# sudo su -c "echo blacklist usb-storage >> /etc/modprobe.d/DISASTIG.conf"'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21064r305345_chk'
  tag severity: 'medium'
  tag gid: 'V-219339'
  tag rid: 'SV-219339r610963_rule'
  tag stig_id: 'UBTU-18-010509'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-21063r305346_fix'
  tag 'documentable'
  tag legacy: ['SV-110023', 'V-100919']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
