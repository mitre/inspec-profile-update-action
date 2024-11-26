control 'SV-239543' do
  title 'The Internetwork Packet Exchange (IPX) protocol must be disabled or not installed.'
  desc 'The Internetwork Packet Exchange (IPX) protocol is a network-layer protocol that is no longer in common use. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause SLES for vRealize to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Check that the "IPX" protocol handler is prevented from dynamic loading:

# grep "install ipx /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* 

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the "IPX" protocol handler from dynamic loading:

# echo "install ipx /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42776r662078_chk'
  tag severity: 'medium'
  tag gid: 'V-239543'
  tag rid: 'SV-239543r662080_rule'
  tag stig_id: 'VROM-SL-000620'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42735r662079_fix'
  tag 'documentable'
  tag legacy: ['SV-99207', 'V-88557']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
