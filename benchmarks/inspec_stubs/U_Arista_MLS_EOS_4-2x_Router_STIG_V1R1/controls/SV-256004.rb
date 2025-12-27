control 'SV-256004' do
  title 'The Arista perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an IGP peering with the NIPRNet or to other autonomous systems.'
  desc 'If the static routes to the alternate gateway are being redistributed into an Exterior Gateway Protocol or Interior Gateway Protocol to a NIPRNet gateway, this could make traffic on NIPRNet flow to that particular router and not to the internet Access Point routers. This could not only wreak havoc with traffic flows on NIPRNet, but it could overwhelm the connection from the router to the NIPRNet gateway(s) and also cause traffic destined for outside of NIPRNet to bypass the defenses of the internet Access Points.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone. 

Review the Arista router configuration of the router connecting to the alternate gateway and verify that redistribution of static routes to the alternate gateway is not occurring. 

Verify the BGP and IGP configurations and remove the redistribute static statement if it is configured.

BGP Example:

To verify the BGP configuration, execute the commands "show bgp configuration active" and "show run section router bgp".

router bgp 1500
 no redistribute static 

OSPF Example:

To verify the OSPF configuration, execute the command "show run section router ospf".

router ospf 1
 no redistribute static 

RIP Example:

To verify the RIP configuration, execute the command "show run section router rip".

router rip
no redistribute static

If the static routes to the alternate gateway are being redistributed into BGP or any IGP peering with a NIPRNet gateway or another autonomous system, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure the router so static routes are not redistributed to an alternate gateway into either an Exterior Gateway Protocol or Interior Gateway Protocol to the NIPRNet or to other autonomous systems.

Review the BGP and IGP configurations and remove the redistribute static statement if it is configured.

BGP Example:

router bgp 1500
 no redistribute static 

OSPF Example:

router ospf 1500
 no redistribute static 

RIP Example:

router rip
 no redistribute static'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59680r882352_chk'
  tag severity: 'low'
  tag gid: 'V-256004'
  tag rid: 'SV-256004r882354_rule'
  tag stig_id: 'ARST-RT-000180'
  tag gtitle: 'SRG-NET-000019-RTR-000010'
  tag fix_id: 'F-59623r882353_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
