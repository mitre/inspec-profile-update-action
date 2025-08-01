control 'SV-100339' do
  title 'The SLES for vRealize must have IEEE 1394 (Firewire) disabled unless needed.'
  desc 'Firewire is a common computer peripheral interface. Firewire devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If the SLES for vRealize needs IEEE 1394 (Firewire), this is not applicable.

Check if the firewire module is not disabled:

# grep "install ieee1394 /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no results are returned, this is a finding.'
  desc 'fix', 'Prevent the SLES for vRealize from loading the firewire module:

# echo "install ieee1394 /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89381r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89689'
  tag rid: 'SV-100339r1_rule'
  tag stig_id: 'VRAU-SL-000675'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96431r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
