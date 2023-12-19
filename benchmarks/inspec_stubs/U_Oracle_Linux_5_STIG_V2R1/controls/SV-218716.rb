control 'SV-218716' do
  title 'The system must have IEEE 1394 (Firewire) disabled unless needed.'
  desc 'Firewire is a common computer peripheral interface. Firewire devices may include storage devices with the potential to install malicious software on a system or exfiltrate data.'
  desc 'check', "If the system needs IEEE 1394 (Firewire), this is not applicable.
Check if the Firewire module is not disabled.
# grep 'install ieee1394 /bin/true' /etc/modprobe.conf /etc/modprobe.d/*
If no results are returned, this is a finding."
  desc 'fix', "Prevent the system from loading the Firewire module.
# echo 'install ieee1394 /bin/true' >> /etc/modprobe.conf"
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20191r556565_chk'
  tag severity: 'low'
  tag gid: 'V-218716'
  tag rid: 'SV-218716r603259_rule'
  tag stig_id: 'GEN008500'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20189r556566_fix'
  tag 'documentable'
  tag legacy: ['V-22580', 'SV-63173']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
