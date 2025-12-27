control 'SV-227052' do
  title 'The system must not have 6to4 enabled.'
  desc '6to4 is an IPv6 transition mechanism that involves tunneling IPv6 packets encapsulated in IPv4 packets on an ad-hoc basis.  This is not a preferred transition strategy and increases the attack surface of the system.'
  desc 'check', '# ifconfig -a
If a tunnel interface is displayed with an IPv4 tunnel source address, an IPv6 interface address, and no tunnel destination address, this is a finding.'
  desc 'fix', 'Disable the active 6to4 tunnel.
# ifconfig <tunnel> down

Check the /etc/hostname* files for startup configuration for the tunnel, and edit or delete as appropriate to prevent the tunnel creation on startup.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29214r485525_chk'
  tag severity: 'medium'
  tag gid: 'V-227052'
  tag rid: 'SV-227052r603265_rule'
  tag stig_id: 'GEN007780'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29202r485526_fix'
  tag 'documentable'
  tag legacy: ['SV-26921', 'V-22545']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
