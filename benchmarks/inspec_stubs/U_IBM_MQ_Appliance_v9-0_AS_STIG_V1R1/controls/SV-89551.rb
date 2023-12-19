control 'SV-89551' do
  title 'The MQ Appliance messaging server must produce log records containing information to establish what type of events occurred.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Without being able to establish what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible. 

Log record content that may be necessary to satisfy the requirement of this control includes time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Messaging servers must log all relevant log data that pertains to the messaging server. Examples of relevant data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD/Web server activity, and messaging server-related system process activity.

'
  desc 'check', 'Apply the following check to each queue manager on the MQ Appliance.

Establish an SSH command line session as an admin user.

To access the MQ Appliance CLI, enter:
mqcli

To identify the queue managers, enter:
dspmq

To check config for each queue, enter:
runmqsc [queue mgr name]

At the runmqsc prompt, enter:
DIS QMGR EVENT

Verify the following events are enabled as required.

AUTHOREV, INHIBITEV, STRSTPEV, CMDEV, SSLEV, CONFIGEV, PERFMEV

If any of the required events are not enabled, this is a finding.'
  desc 'fix', 'Ensure each queue is configured to log the following event names:

AUTHOREV
INHIBITEV
STRSTPEV
CMDEV
SSLEV
CONFIGEV
PERFMEV

Use the "runmqsc" command for each queue manager.

runmqsc [queue mgr name]
ALTER QMGR [event name](ENABLED)

Enter "end" to exit the MQ Appliance CLI.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74735r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74877'
  tag rid: 'SV-89551r1_rule'
  tag stig_id: 'MQMH-AS-000210'
  tag gtitle: 'SRG-APP-000095-AS-000056'
  tag fix_id: 'F-81493r1_fix'
  tag satisfies: ['SRG-APP-000095-AS-000056', 'SRG-APP-000093-AS-000054', 'SRG-APP-000096-AS-000059', 'SRG-APP-000097-AS-000060', 'SRG-APP-000098-AS-000061', 'SRG-APP-000099-AS-000062', 'SRG-APP-000100-AS-000063', 'SRG-APP-000101-AS-000072']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-001462', 'CCI-001487']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-14 (2)', 'AU-3 f']
end
