control 'SV-219340' do
  title 'The Ubuntu operating system must configure the uncomplicated firewall to rate-limit impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of the Ubuntu operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', %q(Verify an application firewall is configured to rate limit any connection to the system.

Check that the Uncomplicated Firewall is configured to rate limit any connection to the system with the following command:

$ sudo ufw show user-rules

IPV4 (user):

Chain ufw-user-input (1 references)

    pkts      bytes target     prot opt in     out     source               destination

       1       52 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22 /* 'dapp_OpenSSH' */

       0        0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443

 

Chain ufw-user-forward (1 references)

    pkts      bytes target     prot opt in     out     source               destination

 

Chain ufw-user-output (1 references)

    pkts      bytes target     prot opt in     out     source               destination

 

Chain ufw-user-limit-accept (0 references)

    pkts      bytes target     prot opt in     out     source               destination

       0        0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0

 

Chain ufw-user-limit (0 references)

    pkts      bytes target     prot opt in     out     source               destination

       0        0 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0            limit: avg 3/min burst 5 LOG flags 0 level 4 prefix "[UFW LIMIT BLOCK] "

       0        0 REJECT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            reject-with icmp-port-unreachable

If any service is not rate limited by the Uncomplicated Firewall, this is a finding.)
  desc 'fix', 'Configure the application firewall to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring the Ubuntu operating system is implementing rate-limiting measures on impacted network interfaces.

Run the following command replacing "[service]" with the service that needs to be rate limited.

$ sudo ufw limit [service]

Or rate-limiting can be done on an interface. An example of adding a rate-limit on the eth0 interface:

$ sudo ufw limit in on eth0'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21065r802373_chk'
  tag severity: 'medium'
  tag gid: 'V-219340'
  tag rid: 'SV-219340r802375_rule'
  tag stig_id: 'UBTU-18-010512'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-21064r802374_fix'
  tag 'documentable'
  tag legacy: ['SV-110005', 'V-100901']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
