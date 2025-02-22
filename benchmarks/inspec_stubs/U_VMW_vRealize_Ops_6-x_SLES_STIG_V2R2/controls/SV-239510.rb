control 'SV-239510' do
  title 'The SLES for vRealize must have USB Mass Storage disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If SLES for vRealize needs USB storage, this vulnerability is not applicable.

Check if the "usb-storage" module is prevented from loading:

# grep "install usb-storage /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no results are returned, this is a finding.'
  desc 'fix', 'Prevent the "usb-storage" module from loading:

# echo "install usb-storage /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42743r661979_chk'
  tag severity: 'medium'
  tag gid: 'V-239510'
  tag rid: 'SV-239510r661981_rule'
  tag stig_id: 'VROM-SL-000445'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-42702r661980_fix'
  tag 'documentable'
  tag legacy: ['SV-99141', 'V-88491']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
