control 'SV-89475' do
  title 'The MQ Appliance messaging server must provide an immediate warning to the SA and ISSO, at a minimum, when allocated log record storage volume reaches 75% of maximum log record storage capacity.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required.  Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded.  Notification of the storage condition will allow administrators to take actions so that logs are not lost.  This requirement can be met by configuring the messaging server to utilize a dedicated logging tool that meets this requirement.'
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

If "QDEPTHHI" is not "75", this is a finding.

Ask the system administrator to demonstrate how they monitor an alert on MQ  failure events.

Verify alarming is set for the following log events:
MQRC_Q_FULL, MQRC_Q_MGR_NOT_ACTIVE, MQRC_Q_DEPTH_HIGH

If the system admin does not monitor an alarm for the following error codes: MQRC_Q_FULL, MQRC_Q_MGR_NOT_ACTIVE, or MQRC_Q_DEPTH_HIGH, this is a finding.'
  desc 'fix', 'For each queue manager on the MQ Appliance, enable performance (PERFMEV) event logging.

From the MQ Appliance CLI, enter the following:

runmqsc [queue mgr name]
ALTER QMGR PERFMEV(ENABLED)
ALTER QLOCAL(SYSTEM.ADMIN.PERFM.EVENT) QDPHIEV(ENABLED)
ALTER QLOCAL(SYSTEM.ADMIN.PERFM.EVENT) QDEPTHHI(75)

Monitor the logs and send alerts based on the following failure codes: 
MQRC_Q_FULL, MQRC_Q_MGR_NOT_ACTIVE, MQRC_Q_DEPTH_HIGH.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74659r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74801'
  tag rid: 'SV-89475r1_rule'
  tag stig_id: 'MQMH-AS-000640'
  tag gtitle: 'SRG-APP-000359-AS-000065'
  tag fix_id: 'F-81417r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
