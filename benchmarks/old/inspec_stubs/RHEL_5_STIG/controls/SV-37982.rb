control 'SV-37982' do
  title 'The system must have USB Mass Storage disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices with the potential to install malicious software on a system or exfiltrate data'
  desc 'fix', "Prevent the usb-storage module from loading.
# echo 'install usb-storage /bin/true' >> /etc/modprobe.conf"
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-22579'
  tag rid: 'SV-37982r1_rule'
  tag stig_id: 'GEN008480'
  tag gtitle: 'GEN008480'
  tag fix_id: 'F-32519r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
