control 'SV-216163' do
  title 'The operating system must prevent internal users from sending out packets which attempt to manipulate or spoof invalid IP addresses.'
  desc 'Manipulation of IP addresses can allow untrusted systems to appear as trusted hosts, bypassing firewall and other security mechanism and resulting in system penetration.'
  desc 'check', %q(Determine the zone that you are currently securing.

# zonename

If the command output is "global", then only the "phys" and "SR-IOV" interfaces assigned to the global zone require inspection. If using a non-Global zone, then all "phys" and "SR-IOV" interfaces assigned to the zone require inspection.

Identify if this system has physical interfaces. 

# dladm show-link -Z | grep -v vnic 
LINK                ZONE      CLASS     MTU    STATE    OVER
net0                global    phys      1500   unknown  --
e1000g0             global    phys      1500   up       --
e1000g1             global    phys      1500   up       --
zoneD/net2          zoneD     iptun     65515  up       --

If "phys" appears in the third column, then the interface is physical.   

For each physical interface, determine if the network interface is Ethernet or InfiniBand:

# dladm show-phys [interface name]
LINK              MEDIA                STATE      SPEED  DUPLEX    DEVICE
[name]            Ethernet             unknown    0      half      dnet0

The second column indicates either "Ethernet" or "Infiniband".

For each physical interface, determine if the host is using ip-forwarding:

# ipadm show-ifprop [interface name] | grep forwarding
[name]      forwarding      ipv4  rw   off        --         off        on,off
[name]      forwarding      ipv6  rw   off        --         off        on,off

If "on" appears in the fifth column, then the interface is using ip-forwarding.

For each interface, determine if the host is using SR-IOV’s Virtual Function (VF) driver:

# dladm show-phys [interface name] | grep vf

If the sixth column includes 'vf' in its name, it is using SR-IOV (ex: ixgbevf0).

For each physical and SR-IOV interface, determine if network link protection capabilities are enabled.

# dladm show-linkprop -p protection
LINK    PROPERTY    PERM   VALUE         DEFAULT   POSSIBLE
net0    protection  rw     mac-nospoof,  --        mac-nospoof,
                           restricted,             restricted,
                           ip-nospoof,             ip-nospoof,
                           dhcp-nospoof            dhcp-nospoof

If the interface uses Infiniband and if restricted, ip-nospoof, and dhcp-nospoof do not appear in the "VALUE" column, this is a finding.

If the interface uses ip-forwarding and if mac-nospoof, restricted, and dhcp-nospoof do not appear in the "VALUE" column, this is a finding.

If the interface uses SR-IOV and if mac-nospoof, restricted, and dhcp-nospoof do not appear in the "VALUE" column, this is a finding.

If the interface uses Ethernet without IP forwarding and if mac-nospoof, restricted, ip-nospoof, and dhcp-nospoof do not appear in the "VALUE" column, this is a finding.)
  desc 'fix', 'Determine the name of the zone that you are currently securing.

# zonename

If the command output is "global", then only the "phys" and "SR-IOV" interfaces assigned to the global zone require configuration. If using a non-Global zone, then all "phys" and "SR-IOV" interfaces assigned to the zone require configuration.

The Network Link Security profile is required.

Determine which network interfaces are available and what protection modes are enabled and required.

Enable link protection based on each configured network interface type.

For InfiniBand:
# pfexec dladm set-linkprop -p protection=restricted,ip-nospoof,dhcp-nospoof [interface name]  

For IP forwarding:
# pfexec dladm set-linkprop -p protection=mac-nospoof,restricted,dhcp-nospoof [interface name] 

For SR-IOV:
# pfexec dladm set-linkprop -p protection=mac-nospoof,restricted,dhcp-nospoof [interface name] 

For Ethernet without IP forwarding:
# pfexec dladm set-linkprop -p protection=mac-nospoof,restricted,ip-nospoof,dhcp-nospoof [interface name]'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17401r372871_chk'
  tag severity: 'medium'
  tag gid: 'V-216163'
  tag rid: 'SV-216163r603268_rule'
  tag stig_id: 'SOL-11.1-050470'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17399r372872_fix'
  tag 'documentable'
  tag legacy: ['V-48191', 'SV-61063']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
