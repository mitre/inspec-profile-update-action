control 'SV-89521' do
  title 'The MQ Appliance messaging server, when categorized as a high level system, must be in a high-availability (HA) cluster.'
  desc "A high level system is a system that handles data vital to the organization's operational readiness or effectiveness of deployed or contingency forces.  A high level system must maintain the highest level of integrity and availability.  By HA clustering the messaging server, the hosted application and data are given a platform that is load-balanced and provided high-availability.

Rudimentary instructions for determining if HA is set up are included here. To ensure proper configuration, system HA design steps must be taken and implemented. Reference vendor documentation for complete instructions on setting up HA: https://ibm.biz/BdicC7

Note: The queue manager’s data (queues, queue messages etc.) are replicated from the appliance in the primary HA role (first appliance) to the appliance in the secondary HA role (second appliance)."
  desc 'check', 'Request and review system documentation identifying the system categorization level.  If the system categorization is not high, this requirement is NA.  

Ask for and review the HA configuration.

On the either member of the HA pair:
Establish an SSH command line session as an admin user.

To access the MQ Appliance CLI, enter:
mqcli

To run the dspmq command, enter:
dspmq -s -o ha 

Each queue manager that is properly configured for HA should show HA(Replicated). 

If it does not, this is a finding.'
  desc 'fix', 'To configure HA:
1. Use three Ethernet cables to directly connect two appliances together using ports eth1, eth2, and eth3.
2. Configure the three connected MQ Appliance ports (on both appliances) as follows:

Interface  Purpose                                                 IP address/CIDR
eth1           HA group primary interface          x.x.x.x/24
eth2           HA group alternative interface   x.x.x.x/24
eth3           HA Replication interface               x.x.x.x/24

On the second appliance, enter the following command from the MQ Appliance CLI:
prepareha -s [SecretText] -a [eth 1 IPAddress of first appliance] [-t timeout]

On the first appliance, enter the following command:
crthagrp -s [SecretText] -a [eth 1 IPAddress of second appliance]

On the first appliance, stop the first queue manager to be HA enabled:
endmqm [name of queue manager]

Set an HA group:
sethagrp -i [name of queue manager]'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74705r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74847'
  tag rid: 'SV-89521r1_rule'
  tag stig_id: 'MQMH-AS-001330'
  tag gtitle: 'SRG-APP-000435-AS-000069'
  tag fix_id: 'F-81463r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
