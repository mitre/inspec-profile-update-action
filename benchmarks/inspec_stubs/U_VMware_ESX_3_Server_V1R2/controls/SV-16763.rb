control 'SV-16763' do
  title 'ESX Server firewall is not configured to High Security.'
  desc 'ESX Server includes a built in firewall between the service console and the network. To ensure the integrity of the service console, VMware has reduced the number of firewall ports that are open by default. At installation time, the service console firewall is configured to block all incoming and outgoing traffic except for ports 902, 80, 443, and 22, which are used for basic communication with ESX Server. This setting enforces a high level of security for the ESX Server host. Medium Security blocks all incoming traffic except on the default ports (902, 443, 80, and 22), and any ports users specifically open. Outgoing traffic is not blocked. Low Security does not block either incoming or outgoing traffic. This setting is equivalent to removing the firewall. Because the ports open by default on the ESX Server are strictly limited, additional ports may need to be open after installation for third party applications such as management, storage, NTP, etc. For instance, a backup agent may use specific ports such as 13720, 13724, 13782, and 13783.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the ESX server from the Inventory panel.
2. Click the Configuration tab and click Security Profile.
    The VI Client displays a list of currently active incoming and outgoing connections with the 
    corresponding firewall ports.
3. Click Properties to open the Properties dialog box.
     The Firewall Properties dialog box lists all the services and management agents that are  
     configured for the host.  
4. If you do not see the Firewall Properties window, then check proceed to step 7.
5. Review the services enabled to ensure that only the following ports are open:
    Ports that may be open for High Security: 902, 80, 443, and 22.  If only these ports are open, 
    this is not a finding.
6. If there are other ports that are open, request the documentation from the IAO/SA that details 
     the reasons for the additional ports are required.  If no documentation can be produced, 
     this is a finding. 
7.  Verify IPtables are configured on the ESX Server service console by performing the following:

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

If no rules are applied to the INPUT chain for these services, this is a finding.

If this cannot be verified, this is a finding.

Caveat: Medium Security may be used only if additional ports are required to be open and it has been approved and documented by the IAO/SA.'
  desc 'fix', 'Configure the ESX Server firewall to High Security.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16164r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15824'
  tag rid: 'SV-16763r1_rule'
  tag stig_id: 'ESX0320'
  tag gtitle: 'ESX Server firewall is not set to High Security.'
  tag fix_id: 'F-15776r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
