control 'SV-37983' do
  title 'The system must have IEEE 1394 (Firewire) disabled unless needed.'
  desc 'Firewire is a common computer peripheral interface. Firewire devices may include storage devices with the potential to install malicious software on a system or exfiltrate data.'
  desc 'fix', "Prevent the system from loading the firewire module.
# echo 'install ieee1394 /bin/true' >> /etc/modprobe.conf"
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-22580'
  tag rid: 'SV-37983r1_rule'
  tag stig_id: 'GEN008500'
  tag gtitle: 'GEN008500'
  tag fix_id: 'F-32520r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
