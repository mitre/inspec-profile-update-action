control 'SV-227978' do
  title 'The system must have USB Mass Storage disabled unless needed.'
  desc 'USB is a common computer peripheral interface.  USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', "If the system needs a particular USB driver for storage, this vulnerability is not applicable.

Check the current loaded kernel modules:

# modinfo | grep usb_ac
# modinfo | grep usb_as
# modinfo | grep hid
# modinfo | grep scsa2usb
# modinfo | grep usbprn
# modinfo | grep usbser_edge

If any command produces output, this is a finding.

Check the configuration of the /etc/system file:

# grep 'exclude: usb_ac' /etc/system
# grep 'exclude: usb_as' /etc/system
# grep 'exclude: hid' /etc/system
# grep 'exclude: scsa2usb' /etc/system
# grep 'exclude: usbprn' /etc/system
# grep 'exclude: usbser_edge' /etc/system

If no results are returned from any particular command, this is a finding."
  desc 'fix', 'Prevent the USB drivers from loading:
# echo "exclude: usb_ac" >> /etc/system 
# echo "exclude: usb_as" >> /etc/system 
# echo "exclude: hid" >> /etc/system 
# echo "exclude: scsa2usb" >> /etc/system 
# echo "exclude: usbprn" >> /etc/system 
# echo "exclude: usbser_edge" >> /etc/system 

The system must be restarted for these changes to take effect.'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36484r603055_chk'
  tag severity: 'low'
  tag gid: 'V-227978'
  tag rid: 'SV-227978r603266_rule'
  tag stig_id: 'GEN008480'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36448r603056_fix'
  tag 'documentable'
  tag legacy: ['SV-26970', 'V-22579']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
