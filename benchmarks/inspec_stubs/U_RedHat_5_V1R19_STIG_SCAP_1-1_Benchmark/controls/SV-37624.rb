control 'SV-37624' do
  title 'Proxy Address Resolution Protocol (Proxy ARP) must not be enabled on the system.'
  desc 'Proxy ARP allows a system to respond to ARP requests on one interface on behalf of hosts connected to another interface.  If this function is enabled when not required, addressing information may be leaked between the attached network segments.'
  desc 'fix', 'Configure the system to not use proxy ARP.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.proxy_arp=0" and "net.ipv4.conf.default.proxy_arp=0".
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22415'
  tag rid: 'SV-37624r1_rule'
  tag stig_id: 'GEN003608'
  tag gtitle: 'GEN003608'
  tag fix_id: 'F-31661r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
