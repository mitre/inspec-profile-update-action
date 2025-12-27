control 'SV-240413' do
  title 'The system must have USB Mass Storage disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If the system needs USB storage, this vulnerability is not applicable.

Check if "usb-storage" is prevented from loading:

# grep "install usb-storage /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no results are returned, this is a finding.'
  desc 'fix', 'Prevent the "usb-storage" module from loading:

# echo "install usb-storage /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43646r670978_chk'
  tag severity: 'medium'
  tag gid: 'V-240413'
  tag rid: 'SV-240413r670980_rule'
  tag stig_id: 'VRAU-SL-000450'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-43605r670979_fix'
  tag 'documentable'
  tag legacy: ['SV-100253', 'V-89603']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
