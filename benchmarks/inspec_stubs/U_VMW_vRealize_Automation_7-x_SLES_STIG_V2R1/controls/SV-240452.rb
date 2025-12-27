control 'SV-240452' do
  title 'Proxy Neighbor Discovery Protocol (NDP) must not be enabled on the system.'
  desc 'Proxy Neighbor Discovery Protocol (NDP) allows a system to respond to NDP requests on one interface on behalf of hosts connected to another interface. If this function is enabled when not required, addressing information may be leaked between the attached network segments.'
  desc 'check', 'Note: For Appliance OS, proxy_ndp is disabled by default and this is not a finding.

Determine if the system is configured for proxy NDP, and if it is enabled:

more /proc/sys/net/ipv6/conf/*/proxy_ndp

If the file is not found, the kernel is not configured for proxy NDP, and this is not a finding. 

If the file has a value of "0", proxy NDP is not enabled, and this is not a finding. 

If the file has a value of "1", proxy NDP is enabled, and this is a finding.'
  desc 'fix', 'Disable proxy NDP on the system.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43685r671095_chk'
  tag severity: 'medium'
  tag gid: 'V-240452'
  tag rid: 'SV-240452r671097_rule'
  tag stig_id: 'VRAU-SL-000655'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43644r671096_fix'
  tag 'documentable'
  tag legacy: ['SV-100331', 'V-89681']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
