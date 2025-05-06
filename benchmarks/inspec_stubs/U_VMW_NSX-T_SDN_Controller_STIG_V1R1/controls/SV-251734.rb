control 'SV-251734' do
  title 'The NSX-T Controller must be configured as a cluster in active/active mode to preserve any information necessary to determine cause of a system failure and to maintain network operations with least disruption to workload processes and flows.'
  desc 'Failure in a known state can address safety or security in accordance with the mission needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the SDN controller. Preserving network element state information helps to facilitate continuous network operations minimal or no disruption to mission-essential workload processes and flows.'
  desc 'check', 'From the NSX-T Manager web interface, go to System >> Appliances.

Verify there are three NSX-T Managers deployed, a VIP or external load balancer is configured, and the cluster is in a healthy state. 

If there are not three NSX-T Managers deployed and a VIP or external load balancer configured and the cluster is in a healthy state, this is a finding.'
  desc 'fix', %q(To add additional NSX-T Manager appliances do the following:

From the NSX-T Manager web interface, go to System >>Appliances, and then click "Add NSX Appliance". Supply the required information to add additional nodes as needed, up to three total.

To configure NSX-T with a cluster VIP or external load balancer do the following:

From the NSX-T Manager web interface, go to System >> Appliances, and then click "Set Virtual IP", enter a VIP that is part of the same subnet as the other management nodes, and then click "Save".

To configure NSX-T with an external load balancer, setup an external load balancer with the following requirements:

- Configure the external load balancer to control traffic to the NSX Manager nodes.
- Configure the external load balancer to use the round robin method and configure source persistence for the load balancer's virtual IP.
- Create or import a signed certificate and apply the same certificate to all the NSX Manager nodes. The certificate must have the FQDN of the virtual IP and each of the nodes in the SAN.

Note: An external load balancer will not work with the NSX Manager VIP. Do not configure an NSX Manager VIP if using an external load balancer.

If the cluster status is not in a healthy state identify the degraded component on the appliance and troubleshoot the issue with the error information provided.)
  impact 0.5
  ref 'DPMS Target VMware NSX-T SDN Controller'
  tag check_id: 'C-55171r810058_chk'
  tag severity: 'medium'
  tag gid: 'V-251734'
  tag rid: 'SV-251734r810060_rule'
  tag stig_id: 'TSDC-3X-000011'
  tag gtitle: 'SRG-NET-000236-SDN-000365'
  tag fix_id: 'F-55125r810059_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
