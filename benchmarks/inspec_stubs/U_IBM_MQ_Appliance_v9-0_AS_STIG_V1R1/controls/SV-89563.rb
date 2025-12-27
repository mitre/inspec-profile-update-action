control 'SV-89563' do
  title 'The MQ Appliance messaging server must provide a log reduction capability that supports on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including after the log data has been subjected to log reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

Log reduction is a process that manipulates collected log information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad-hoc, and as-needed) reports.

To fully understand and investigate an incident within the components of the messaging server, the messaging server, when providing a reduction capability, must provide an on-demand reporting capability.

Instructions for using the amqsevt sample program to display instrumentation events may be found at the following URL: https://ibm.biz/BdsCzY

"
  desc 'check', 'Confirm that the following command is available and functioning on an authorized MQ client device:

amqsevt -m [queue mgr name] {-q SYSTEM.ADMIN.QMGR.EVENT | -q SYSTEM.ADMIN.CONFIG.EVENT | -q SYSTEM.ADMIN.PERFM.EVENT | -q SYSTEM.ADMIN.CHANNEL.EVENT | -q SYSTEM.ADMIN.COMMAND.EVENT} -c -u [user name]

If an MQ client application is not enabled to monitor one or more of the above event queues, this is a finding.'
  desc 'fix', 'Log record aggregation and reporting for each event-logging-enabled queue manager on the MQ Appliance may be accomplished by running the following command from an authorized MQ client device:

amqsevt -m [queue mgr name] {-q SYSTEM.ADMIN.QMGR.EVENT | -q SYSTEM.ADMIN.CONFIG.EVENT | -q SYSTEM.ADMIN.PERFM.EVENT | -q SYSTEM.ADMIN.CHANNEL.EVENT | -q SYSTEM.ADMIN.COMMAND.EVENT} -c -u [user name]

Note: Any MQ monitoring solution that can connect to MQ as a client may be used to monitor event queues.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74747r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74889'
  tag rid: 'SV-89563r1_rule'
  tag stig_id: 'MQMH-AS-000870'
  tag gtitle: 'SRG-APP-000181-AS-000255'
  tag fix_id: 'F-81505r1_fix'
  tag satisfies: ['SRG-APP-000181-AS-000255', 'SRG-APP-000355-AS-000055']
  tag 'documentable'
  tag cci: ['CCI-001876', 'CCI-001920']
  tag nist: ['AU-7 a', 'AU-14 (3)']
end
