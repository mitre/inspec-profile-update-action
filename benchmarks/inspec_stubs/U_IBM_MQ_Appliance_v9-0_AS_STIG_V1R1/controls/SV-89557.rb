control 'SV-89557' do
  title 'The MQ Appliance messaging server must alert the SA and ISSO, at a minimum, in the event of a log processing failure.'
  desc 'Logs are essential to monitor the health of the system, investigate changes that occurred to the system, or investigate a security incident. When log processing fails, the events during the failure can be lost. To minimize the timeframe of the log failure, an alert needs to be sent to the SA and ISSO at a minimum.

Log processing failures include, but are not limited to, failures in the messaging server log capturing mechanisms or log storage capacity being reached or exceeded. In some instances, it is preferred to send alarms to individuals rather than to an entire group. Messaging servers must be able to trigger an alarm and send an alert to, at a minimum, the SA and ISSO in the event there is a messaging server log processing failure.

It is the responsibility of the MQ system administrator to monitor the SYSTEM.ADMIN.PERFM.EVENT queue and provide appropriate notification. 

All MQ installations provide a sample program, amqsevt. This program reads messages from event queues, and formats them into readable strings.

An event logging failure would be indicated by one of the following return codes: MQRC_Q_FULL, MQRC_Q_MGR_NOT_ACTIVE, or MQRC_Q_DEPTH_HIGH

Note: Any MQ monitoring solution that connects to MQ as a client may be used to monitor event queues.

'
  desc 'check', 'For each queue manager on the MQ Appliance for which performance events logging should be enabled, establish an SSH command line session as an admin user.

To access the MQ Appliance CLI, enter:
mqcli

To identify the queue managers, enter:
dspmq

To run the "runmqsc [queue mgr name]" command for each running queue manager identified, enter:
runmqsc [queue mgr name]
DIS QMGR PERFMEV
DIS QLOCAL(SYSTEM.ADMIN.PERFM.EVENT) QDPHIEV
end

If "QDPHIEV" or "PERFMEV" is not "ENABLED", this is a finding.

Ask the system administrator to demonstrate how they monitor an alert on MQ failure events.

Verify alarming is set for the following log events:
MQRC_Q_FULL, MQRC_Q_MGR_NOT_ACTIVE, MQRC_Q_DEPTH_HIGH

If the system admin does not monitor an alarm for the following error codes: MQRC_Q_FULL, MQRC_Q_MGR_NOT_ACTIVE, or MQRC_Q_DEPTH_HIGH, this is a finding.'
  desc 'fix', 'For each queue manager on the MQ Appliance, enable performance (PERFMEV) event logging.

From the MQ Appliance CLI, enter the following:

runmqsc [queue mgr name]
ALTER QMGR PERFMEV(ENABLED)
ALTER QLOCAL(SYSTEM.ADMIN.PERFM.EVENT) QDPHIEV(ENABLED)

Monitor the logs that send alerts based on the following failure codes: 
MQRC_Q_FULL, MQRC_Q_MGR_NOT_ACTIVE, MQRC_Q_DEPTH_HIGH.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74741r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74883'
  tag rid: 'SV-89557r1_rule'
  tag stig_id: 'MQMH-AS-000610'
  tag gtitle: 'SRG-APP-000108-AS-000067'
  tag fix_id: 'F-81499r1_fix'
  tag satisfies: ['SRG-APP-000108-AS-000067', 'SRG-APP-000360-AS-000066']
  tag 'documentable'
  tag cci: ['CCI-000139', 'CCI-001858']
  tag nist: ['AU-5 a', 'AU-5 (2)']
end
