control 'SV-99213' do
  title 'Proxy Neighbor Discovery Protocol (NDP) must not be enabled on SLES for vRealize.'
  desc 'Proxy Neighbor Discovery Protocol (NDP) allows a system to respond to NDP requests on one interface on behalf of hosts connected to another interface. If this function is enabled when not required, addressing information may be leaked between the attached network segments.'
  desc 'check', 'Determine if SLES for vRealize has proxy "NDP", and if it is enabled:

# more /proc/sys/net/ipv6/conf/*/proxy_ndp

If the file is not found, the kernel does not have proxy "NDP", this is not a finding.

If the file has a value of "0", proxy "NDP" is not enabled, this is not a finding.

If the file has a value of "1", proxy NDP is enabled, this is a finding.'
  desc 'fix', 'Disable proxy "NDP" on the system.

For Appliance OS, "proxy_ndp" is disabled by default.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88255r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88563'
  tag rid: 'SV-99213r1_rule'
  tag stig_id: 'VROM-SL-000635'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95305r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
