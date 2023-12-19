control 'SV-89565' do
  title 'The MQ Appliance messaging server must be configured to fail over to another system in the event of log subsystem failure.'
  desc 'This requirement is dependent upon system MAC and availability. If the system MAC and availability do not specify redundancy requirements, this requirement is NA.

It is critical that, when a system is at risk of failing to process logs as required, it detects and takes action to mitigate the failure.

Messaging servers must be capable of failing over to another system which can handle application and logging functions upon detection of an application log processing failure. This will allow continual operation of the application and logging functions while minimizing the loss of operation for the users and loss of log data.

To ensure proper configuration, system HA design steps must be taken and implemented. Reference vendor documentation for complete instructions on setting up HA: https://ibm.biz/BdicC7

'
  desc 'check', 'In the event of a MQ queue manager failure, an HA configuration must be used. 

Obtain system documentation identifying the HA configuration.

Establish an SSH command line session to either of the pair as an admin user.

To access the MQ Appliance CLI, enter:
mqcli

To run the dspmq command, enter:
dspmq -s -o ha 

Each queue manager that is properly configured for HA should show HA(Replicated). 

If it does not, this is a finding.'
  desc 'fix', 'Rudimentary instructions for setting up HA are included here. 

1. Use three Ethernet cables to directly connect two appliances together using ports eth1, eth2, and eth3.
2. Configure the three connected MQ Appliance ports (on both appliances) as follows:

Interface Purpose IP address/CIDR
eth1 HA group primary interface x.x.x.x/24
eth2 HA group alternative interface x.x.x.x/24
eth3 HA Replication interface x.x.x.x/24

On the second appliance, enter the following command from the MQ Appliance CLI:
prepareha -s [SecretText] -a [eth 1 IPAddress of first appliance] [-t timeout]

On the first appliance, enter the following command:
crthagrp -s [SecretText] -a [eth 1 IPAddress of second appliance]

On the first appliance, stop the first queue manager to be HA enabled:
endmqm [name of queue manager]

Set an HA group:
sethagrp -i [name of queue manager]

Note: The queue manager’s data (queues, queue messages, etc.) are replicated from the appliance in the primary HA role (first appliance) to the appliance in the secondary HA role (second appliance).'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74891'
  tag rid: 'SV-89565r1_rule'
  tag stig_id: 'MQMH-AS-000900'
  tag gtitle: 'SRG-APP-000109-AS-000070'
  tag fix_id: 'F-81507r1_fix'
  tag satisfies: ['SRG-APP-000109-AS-000070', 'SRG-APP-000109-AS-000068', 'SRG-APP-000125-AS-000084']
  tag 'documentable'
  tag cci: ['CCI-000140', 'CCI-001348']
  tag nist: ['AU-5 b', 'AU-9 (2)']
end
