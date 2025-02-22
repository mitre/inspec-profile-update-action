control 'SV-89567' do
  title 'The MQ Appliance messaging server must provide a clustering capability.'
  desc 'This requirement is dependent upon system criticality and confidentiality requirements. If the system categorization and confidentiality levels do not specify redundancy requirements, this requirement is NA.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. When application failure is encountered, preserving application state facilitates application restart and return to the operational mode of the organization with less disruption of mission/business processes.

Clustering of multiple messaging servers is a common approach to providing fail-safe application availability when system MAC and confidentiality levels require redundancy.

'
  desc 'check', 'Review system categorization to determine if redundancy is a requirement. If the system categorization does not specify redundancy requirements, this requirement is NA.

On each member of the HA pair:
Establish an SSH command line session as an admin user.

To access the MQ Appliance CLI, enter:
mqcli

To run the dspmq command, enter:
dspmq -s -o ha 

One of the appliances should be running as primary, the other as secondary.

If HA is not configured and the primary and secondary running, this is a finding.'
  desc 'fix', 'To configure HA:
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
crtmqm [HA QM name] –p [port] –sx

Note: The queue manager’s data (queues, queue messages, etc.) is replicated from the appliance in the primary HA role (first appliance) to the appliance in the secondary HA role (second appliance).'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74893'
  tag rid: 'SV-89567r1_rule'
  tag stig_id: 'MQMH-AS-001260'
  tag gtitle: 'SRG-APP-000225-AS-000154'
  tag fix_id: 'F-81509r1_fix'
  tag satisfies: ['SRG-APP-000225-AS-000154', 'SRG-APP-000225-AS-000166']
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
