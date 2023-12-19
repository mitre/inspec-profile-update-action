control 'SV-89595' do
  title 'The MQ Appliance messaging server must provide access logging that ensures users who are granted a privileged role (or roles) have their privileged activity logged.'
  desc 'In order to be able to provide a forensic history of activity, the messaging server must ensure users who are granted a privileged role or those who utilize a separate distinct account when accessing privileged functions or data have their actions logged.

If privileged activity is not logged, no forensic logs can be used to establish accountability for privileged actions that occur on the system.

Instructions for using the amqsevt sample program to display instrumentation events may be found at the following URL: https://ibm.biz/BdsCzY

'
  desc 'check', 'For each queue manager on the MQ Appliance for which configuration events logging should be enabled, establish an SSH command line session as an admin user.

To access the MQ Appliance CLI, enter:
mqcli

To identify the queue managers, enter:
dspmq

To run the "runmqsc [queue mgr name]" command for each running queue manager, enter:
runmqsc [queue mgr name]
DIS QMGR CONFIGEV
CONFIGEV(ENABLED) - should be the result.
end

If "CONFIGEV" is not "ENABLED", this is a finding.'
  desc 'fix', 'For each queue manager on the MQ Appliance, enable configuration event logging (CONFIGEV).

From the MQ Appliance CLI, enter the following:

runmqsc [queue mgr name]
ALTER QMGR CONFIGEV(ENABLED)
end'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74921'
  tag rid: 'SV-89595r1_rule'
  tag stig_id: 'MQMH-AS-000480'
  tag gtitle: 'SRG-APP-000343-AS-000030'
  tag fix_id: 'F-81537r1_fix'
  tag satisfies: ['SRG-APP-000343-AS-000030', 'SRG-APP-000016-AS-000013', 'SRG-APP-000495-AS-000220', 'SRG-APP-000499-AS-000224', 'SRG-APP-000503-AS-000228', 'SRG-APP-000504-AS-000229', 'SRG-APP-000509-AS-000234']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000172', 'CCI-002234']
  tag nist: ['AC-17 (1)', 'AU-12 c', 'AC-6 (9)']
end
