control 'SV-218485' do
  title 'Proxy Address Resolution Protocol (Proxy ARP) must not be enabled on the system.'
  desc 'Proxy ARP allows a system to respond to ARP requests on one interface on behalf of hosts connected to another interface.  If this function is enabled when not required, addressing information may be leaked between the attached network segments.'
  desc 'check', 'Verify the system does not use proxy ARP.

# grep [01] /proc/sys/net/ipv4/conf/*/proxy_arp|egrep "default|all"

If all of the resulting lines do not end with "0", this is a finding.'
  desc 'fix', 'Configure the system to not use proxy ARP.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.proxy_arp=0" and "net.ipv4.conf.default.proxy_arp=0".
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19960r562597_chk'
  tag severity: 'medium'
  tag gid: 'V-218485'
  tag rid: 'SV-218485r603259_rule'
  tag stig_id: 'GEN003608'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-19958r562598_fix'
  tag 'documentable'
  tag legacy: ['V-22415', 'SV-64201']
  tag cci: ['CCI-000381', 'CCI-001551']
  tag nist: ['CM-7 a', 'AC-4']
end
