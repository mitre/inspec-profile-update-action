control 'SV-218682' do
  title 'The system must not have 6to4 enabled.'
  desc '6to4 is an IPv6 transition mechanism involving tunneling IPv6 packets encapsulated in IPv4 packets on an ad-hoc basis.  This is not a preferred transition strategy and increases the attack surface of the system.'
  desc 'check', 'Check the system for any active 6to4 tunnels without specific remote addresses.

# ip tun list | grep "remote any" | grep "ipv6/ip"

If any results are returned the "tunnel" is the first field.

If any results are returned, this is a finding.'
  desc 'fix', 'Disable the active 6to4 tunnel.

# ip link set <tunnel> down

Add this command to a startup script, or remove the configuration creating the tunnel.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20157r562927_chk'
  tag severity: 'medium'
  tag gid: 'V-218682'
  tag rid: 'SV-218682r603259_rule'
  tag stig_id: 'GEN007780'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20155r562928_fix'
  tag 'documentable'
  tag legacy: ['V-22545', 'SV-63423']
  tag cci: ['CCI-000381', 'CCI-001551']
  tag nist: ['CM-7 a', 'AC-4']
end
