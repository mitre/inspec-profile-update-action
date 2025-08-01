control 'SV-99215' do
  title 'The SLES for vRealize must not have 6to4 enabled.'
  desc '6to4 is an IPv6 transition mechanism that involves tunneling IPv6 packets encapsulated in IPv4 packets on an ad hoc basis. This is not a preferred transition strategy and increases the attack surface of SLES for vRealize.'
  desc 'check', 'Check SLES for vRealize for any active "6to4" tunnels without specific remote addresses:

# ip tun list | grep "remote any" | grep "ipv6/ip"

If any results are returned the "tunnel" is the first field. 

If any results are returned, this is a finding.'
  desc 'fix', 'Disable the active "6to4" tunnel:

# ip link set <tunnel> down

Add this command to a startup script, or remove the configuration creating the tunnel.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88257r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88565'
  tag rid: 'SV-99215r1_rule'
  tag stig_id: 'VROM-SL-000640'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95307r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
