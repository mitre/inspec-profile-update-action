control 'SV-16765' do
  title 'IP tables or internal router/firewall is not configured to restrict IP addresses to services.'
  desc 'The service console is a privileged virtual machine with interfaces into the VMkernel. In earlier releases, the service console was the main interface, whereas in ESX Server 3 and later, the VI Client is the primary interface. The service console is now used for advanced administration and system management functions such as HTTP, SNMP, and API interfaces. There are several processes and services that run in the service console which include the following: hostd, authd, net-snmp.  To protect these important services on the service console, access control lists will be utilized to ensure only authorized IP addresses are able to access these services.'
  desc 'check', '1. If check ESX0320 was not a finding, then this check is not a finding. If it was a finding, then proceed to step 2. 
2. Ask the IAO/SA what device is being used to restrict these services.  If it is a router or  
    firewall, then work with the network reviewer or system administrator to verify compliance.
3. If it is not a router/firewall, then review the IPtables configuration.  Verify IPtables are configured on the ESX Server service console by performing the following:

# iptables –L | grep hostd

The displayed result should look similar to the following:

iptables –A INPUT -d <IP Addresses Allowed> –p tcp –dport 443 –j Accept  //hostd
iptables –A INPUT -d <IP Addresses Allowed> –p tcp –dport 80 –j Accept  //hostd

# iptables –L | grep authd 

The displayed result should look similar to the following:

iptables –A INPUT  -d <IP Addresses Allowed> –p tcp –dport  902 –j Accept  //authd

# iptables –L | grep snmpd

The displayed result should look similar to the following:

iptables –A INPUT  -d <IP Addresses Allowed> –p tcp –dport 161 –j Accept  //snmpd

At the bottom of the INPUT chain you should see the following:

iptables –A INPUT –j REJECT  //deny all rule at end of chain

If no rules are applied to the INPUT chain for these services,  this is a finding.

If this cannot be verified, this is a finding.

Note: ESX Server 3.x uses hostd for the server daemon and it is not configurable with TCP wrappers. Hostd listens on http/https ports.'
  desc 'fix', 'Restrict access to the ESX Server services to only authorized IP addresses.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16168r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15826'
  tag rid: 'SV-16765r1_rule'
  tag stig_id: 'ESX0340'
  tag gtitle: 'ESX services are not restricted by IP addresses.'
  tag fix_id: 'F-15778r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
