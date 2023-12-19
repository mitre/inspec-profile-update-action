control 'SV-89525' do
  title 'The MQ Appliance messaging server must, at a minimum, transfer the logs of interconnected systems in real time, and transfer the logs of standalone systems weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.  Protecting log data is important during a forensic investigation to ensure investigators can track and understand what may have occurred.  Off-loading should be set up as a scheduled task but can be configured to be run manually, if other processes during the off-loading are manual.

Off-loading is a common process in information systems with limited log storage capacity.  

The MQ appliance is designed to be used in a redundant configuration which will ensure duplicates of log activity are created.

Rudimentary instructions for determining if HA is set up are included here. To ensure proper configuration, system HA design steps must be taken and implemented. Reference vendor documentation for complete instructions on setting up HA: https://ibm.biz/BdicC7

Note: The queue manager’s data (queues, queue messages etc.) are replicated from the appliance in the primary HA role (first appliance) to the appliance in the secondary HA role (second appliance).'
  desc 'check', 'Review system categorization to determine if redundancy is a requirement. If system categorization does not specify redundancy, interview system administrator to determine how they have configured the weekly transfer of logs for the MQ appliance.

For redundant systems: On each member of the HA pair:
Establish an SSH command line session as an admin user.

To access the MQ Appliance CLI, enter:
mqcli

To run the dspmq command, enter:
dspmq -s -o ha 

One of the appliances should be running as primary, the other as secondary.

If HA is not configured with the primary and secondary running, or if there is no MQ log transfer taking place on a standalone system on a weekly basis, this is a finding.'
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
crtmqm [HA QM name] –p [port] –sx

Note: The queue manager’s data (queues, queue messages, etc.) is replicated from the appliance in the primary HA role (first appliance) to the appliance in the secondary HA role (second appliance).'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74709r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74851'
  tag rid: 'SV-89525r1_rule'
  tag stig_id: 'MQMH-AS-001310'
  tag gtitle: 'SRG-APP-000515-AS-000203'
  tag fix_id: 'F-81467r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
