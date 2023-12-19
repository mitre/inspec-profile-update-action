control 'SV-256006' do
  title 'The out-of-band management (OOBM) Arista gateway router must be configured to not redistribute routes between the management network routing domain and the managed network routing domain.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries; otherwise, it is possible that management traffic will not be separated from production traffic.

Since the managed network and the management network are separate routing domains, separate Interior Gateway Protocol routing instances must be configured on the router, one for the managed network and one for the OOBM network. In addition, the routes from the two domains must not be redistributed to each other.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Verify the Interior Gateway Protocol instance used for the managed network does not redistribute routes into the Interior Gateway Protocol instance used for the management network and vice versa.

PROD IGP Routing Domain:

Step 1: To verify interfaces and vrf instance are configured, execute the command "show run int YY".

interface Et3/17/1
 description To_PROD
 ip address 10.1.12.1/24

Step 2: Verify the OSPF configuration, the PROD subnet is advertised, and IGP redistribution is removed in the OSPF process. To verify the OSPF configuration, execute the command "show run section router ospf".

router ospf 100 vrf PROD
   network 10.1.0.0/24 area 0.0.0.0
   no redistribute rip

OOBM IGP Routing Domain, running on the management network

Step 3: To verify interfaces are configured, execute the command "show run int YY". 

interface Et3/17/2
 description To_OOBM
 ip address 172.16.10.1/24
 
Step 4: Verify the RIP configuration, the OOBM subnet is advertised, and IGP redistribution is removed in the RIP process. To verify the RIP configuration, execute the command "show run section router rip".

router rip
   network 172.16.10.0/24 
   no redistribute ospf
   no shutdown

If the Interior Gateway Protocol instance used for the managed network redistributes routes into the Interior Gateway Protocol instance used for the management network or vice versa, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure the Interior Gateway Protocol instance used for the managed network to prohibit redistribution of routes into the Interior Gateway Protocol instance used for the management network and vice versa.

PROD IGP Routing Domain:

Step 1: Configure the interface.

interface Et3/17/1
 description To_PROD
 ip address 10.1.12.1/24

Step 2: Configure the OSPF process to remove the IGP redistribution.

router ospf 100
   network 10.1.0.0/24 area 0.0.0.0
   no redistribute rip

OOBM IGP Routing Domain, running on the management network

Step 3: Configure the interface.

interface Et3/17/1
 description To_OOBM
 ip address 172.16.10.1/24
 
Step 4: Configure the RIP process to remove the IGP redistribution.

router rip
   network 172.16.10.0/24 
   no redistribute ospf
   no shutdown'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59682r882358_chk'
  tag severity: 'medium'
  tag gid: 'V-256006'
  tag rid: 'SV-256006r882360_rule'
  tag stig_id: 'ARST-RT-000200'
  tag gtitle: 'SRG-NET-000019-RTR-000012'
  tag fix_id: 'F-59625r882359_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
