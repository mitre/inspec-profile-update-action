control 'SV-89415' do
  title 'The MQ Appliance messaging server must off-load log records onto a different system or media from the system being logged.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, access control or flow control rules invoked.

Off-loading is a common process in information systems with limited log storage capacity.

Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Messaging servers and their related components are required to off-load log records onto a different system or media than the system being logged.

An HA configuration provides real-time synchronous replication of the logs to a mirrored MQ Appliance.'
  desc 'check', 'Review system categorization to determine if redundancy is a requirement. If system categorization does not specify redundancy, interview system administrator to determine how they have configured the MQ appliance to off-load log files onto a different system.  

Perform on each member of the HA pair.

To access the MQ Appliance CLI, enter:
mqcli

dspmq -s -o ha

One of the appliances should be running as primary, the other as secondary.

If HA is not configured with the primary and secondary running, or if there is no mechanism implemented to off-load log records, this is a finding.'
  desc 'fix', 'To configure HA:
1. Use three Ethernet cables to directly connect two appliances together using ports eth1, eth2, and eth3.
2. Configure the three connected MQ Appliance ports (on both appliances) as follows:

Interface  Purpose                                              IP address/CIDR
eth1           HA group primary interface           x.x.x.x/24
eth2           HA group alternative interface     x.x.x.x/24
eth3           HA Replication interface                x.x.x.x/24

On the second appliance, enter the following command from the MQ Appliance CLI:
prepareha -s [SecretText] -a [eth 1 IPAddress of first appliance] [-t timeout]

On the first appliance, enter the following command from the MQ Appliance CLI:
crthagrp -s [SecretText] -a [eth 1 IPAddress of second appliance]
crtmqm [HA QM name] –p [port] –sx

Note: The queue manager’s data (queues, queue messages, etc.) is replicated from the appliance in the primary HA role (first appliance) to the appliance in the secondary HA role (second appliance).'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74597r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74741'
  tag rid: 'SV-89415r1_rule'
  tag stig_id: 'MQMH-AS-000150'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag fix_id: 'F-81357r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
