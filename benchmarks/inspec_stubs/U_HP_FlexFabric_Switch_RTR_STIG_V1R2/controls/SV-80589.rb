control 'SV-80589' do
  title 'The HP FlexFabric Switch must not redistribute static routes to alternate gateway service provider into an Exterior Gateway Protocol or Interior Gateway Protocol to the NIPRNet or to other Autonomous System.'
  desc 'If the static routes to the alternate gateway are being redistributed into an Exterior Gateway Protocol or Interior Gateway Protocol to a NIPRNet gateway, this could make traffic on NIPRNet flow to that particular router and not to the Internet Access Point routers. This could not only wreak havoc with traffic flows on NIPRNet, but it could overwhelm the connection from the router to the NIPRNet gateway(s) and also cause traffic destined for outside of NIPRNet to bypass the defenses of the Internet Access Points.'
  desc 'check', 'Review the External/internal gateway protocol database on the HP FlexFabric Switch to ensure no static routes are being redistributed via these protocols. 

If there are static routes being re-distributed, this is a finding.

[HP] display ospf lsdb

         OSPF Process 1 with HP FlexFabric Switch ID 5.9.2.0
                 Link State Database


                         Area: 0.0.0.1
 Type      LinkState ID    AdvHP FlexFabric Switch       Age   Len   Sequence  Metric
 HP FlexFabric Switch    1.1.1.1           1.1.1.1            1644  48    80000155  0
 HP FlexFabric Switch    5.9.2.0           5.9.2.0            233    48    8000013E  0
 HP FlexFabric Switch    2.2.2.2           2.2.2.2            294    72    8000014F  0

                 AS External Database
 Type         LinkState ID    AdvHP FlexFabric Switch       Age  Len   Sequence  Metric
 External  16.0.0.0           5.9.2.0             233  36    80000001  1
 External  15.252.0.0      5.9.2.0             233  36    80000001  1

Note: In the example above we see two external entries with the advertising HP FlexFabric Switch as the HP FlexFabric Switch. This exists when the HP FlexFabric Switch is configured to redistribute static route.'
  desc 'fix', 'By default the HP FlexFabric switches do not redistribute static routes via External/Internak gateway protocols. If Static routes redistribution has been configure, use the command bellow to disable it.

[HP] ospf 1
[HP-ospf-1] undo import-route static'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66099'
  tag rid: 'SV-80589r1_rule'
  tag stig_id: 'HFFS-RT-000002'
  tag gtitle: 'SRG-NET-000019-RTR-000011'
  tag fix_id: 'F-72175r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
