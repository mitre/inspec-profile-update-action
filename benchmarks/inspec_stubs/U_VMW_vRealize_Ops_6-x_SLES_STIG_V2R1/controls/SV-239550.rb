control 'SV-239550' do
  title 'The SLES for vRealize must have IEEE 1394 (Firewire) disabled unless needed.'
  desc 'Firewire is a common computer peripheral interface. Firewire devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If SLES for vRealize needs IEEE 1394 (Firewire), this is not applicable.

Check if the firewire module is not disabled:

# grep "install ieee1394 /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no results are returned, this is a finding.'
  desc 'fix', 'Prevent SLES for vRealize from loading the firewire module:

# echo "install ieee1394 /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42783r662099_chk'
  tag severity: 'medium'
  tag gid: 'V-239550'
  tag rid: 'SV-239550r662101_rule'
  tag stig_id: 'VROM-SL-000655'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42742r662100_fix'
  tag 'documentable'
  tag legacy: ['SV-99221', 'V-88571']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
