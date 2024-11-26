control 'SV-99141' do
  title 'The SLES for vRealize must have USB Mass Storage disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If SLES for vRealize needs USB storage, this vulnerability is not applicable.

Check if the "usb-storage" module is prevented from loading:

# grep "install usb-storage /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no results are returned, this is a finding.'
  desc 'fix', 'Prevent the "usb-storage" module from loading:

# echo "install usb-storage /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88183r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88491'
  tag rid: 'SV-99141r1_rule'
  tag stig_id: 'VROM-SL-000445'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-95233r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
