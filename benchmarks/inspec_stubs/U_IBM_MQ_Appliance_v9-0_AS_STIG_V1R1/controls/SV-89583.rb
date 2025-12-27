control 'SV-89583' do
  title 'The MQ Appliance messaging server must generate log records for access and authentication events.'
  desc 'Log records can be generated from various components within the messaging server. From a messaging server perspective, certain specific messaging server functionalities may be logged as well. The messaging server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the messaging server must be able to facilitate these changes.

The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events.'
  desc 'check', 'Establish an SSH command line session as an admin user.

To access the MQ Appliance CLI, enter:
mqcli

To identify the queue managers, enter:
dspmq

For each queue manager identified, run the command:
runmqsc [queue name]

DIS QMGR EVENT

A list of all events will be displayed along with an indication of if event logging is enabled. The events are as follows:

Authority: AUTHOREV, Inhibit: INHIBITEV, Local: LOCALEV, Remote: REMOTEEV, Start and stop: STRSTPEV, Performance: PERFMEV, Command: CMDEV, Channel: CHLEV, Channel auto definition: CHADEV, SSL: SSLEV, Configuration: CONFIGEV

If and required event logging is not enabled for running queue managers, this is a finding.'
  desc 'fix', 'The following events may be logged for each queue manager on the MQ Appliance:

Authority (AUTHOREV), Inhibit (INHIBITEV), Local (LOCALEV), Remote (REMOTEEV), Start and stop (STRSTPEV), Performance (PERFMEV), Command (CMDEV), Channel (CHLEV), Channel auto definition (CHADEV), SSL (SSLEV), Configuration (CONFIGEV)

To enable logging for a queue manager, enter the following from the MQ Appliance CLI for each event for which you wish to enable logging:

To access the MQ Appliance CLI, enter the following:
mqcli 

runmqsc [queue mgr name]
ALTER QMGR [event name](ENABLED)
end

Note: Any MQ monitoring solution that connects to MQ as a client may be used to monitor event queues.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74909'
  tag rid: 'SV-89583r1_rule'
  tag stig_id: 'MQMH-AS-001110'
  tag gtitle: 'SRG-APP-000089-AS-000050'
  tag fix_id: 'F-81525r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
