control 'SV-225632' do
  title 'WebSphere MQ dead letter and alias dead letter queues are not properly defined.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists. Some resources provide the ability to disable or bypass security checking. Failure to properly protect WebSphere MQ resources may result in unauthorized access. This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a) Refer to the following report produced by the  z/OS Data Collection:

- MQSRPT(ssid)

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

b) Review the ssid report(s) and perform the following steps:

1) Find the DISPLAY QMGR DEADQ command to locate the start of the dead-letter queue information. Review the DEADQ parameter to obtain the name of the real dead-letter queue.

2) From the top of the report, find the QUEUE(dead-letter.queue.name) entry to locate the start of the real dead-letter queue definition. Review the GET and PUT parameters to determine their values, and ensure they conform to the specified security requirements.

The  standard values are:

GET(ENABLED)
PUT(ENABLED)

NOTE: Dead-letter.queue.name is the value of the DEADQ parameter determined in Step 1.
 
3) From the top of the report, find the QUEUE(dead-letter.queue.name.PUT) entry to locate the start of the alias dead-letter queue definition. Review the GET and PUT parameters to determine their values, and ensure they conform to those specified in the security requirements.

The standard values are:

GET(DISABLED)
PUT(ENABLED)

NOTE 1: Dead-letter.queue.name is the value of the DEADQ parameter determined in Step 1.

NOTE 2: The TARGQ parameter value for the alias queue will be the real dead letter queue name.

NOTE 3:  If an alias queue is not used in place of the dead-letter queue, then the ACP rules for the dead-letter queue must be coded to restrict unauthorized users and systems from reading the messages on the file.

c) If all of the items in (b) are true, there is no finding.

d) If any item in (b) is untrue, this is a finding.'
  desc 'fix', 'The systems programmer responsible for supporting MQSeries/WebSphere MQ will ensure that the dead-letter queue and its alias are properly defined.

The following scenario describes how to securely define a dead-letter queue:

(1)	Define the real dead-letter queue with attributes PUT(ENABLED) and GET(ENABLED).

(2)	Give update authority for the dead-letter queue to CKTI (the MQSeries/WebSphere MQ-supplied CICS task initiator), channel initiators, and any automated application used for dead-letter queue maintenance.

(3)	Define an alias queue that resolves to the real dead-letter queue, but give the alias queue the attributes PUT(ENABLED) and GET(DISABLED).

(4)	To put a message on the dead-letter queue, an application uses the alias queue. The application does the following:

(a)	Retrieve the name of the real dead-letter queue. To do this, it opens the queue manager object using MQOPEN, and then issues an MQINQ to get the dead-letter queue name.

(b)	Build the name of the alias queue by appending the characters ".PUT" to this name, in this case, ssid.DEAD.QUEUE.PUT.

(c)	Open the alias queue, ssid.DEAD.QUEUE.PUT.

(d)	Put the message on the real dead-letter queue by issuing an MQPUT against the alias queue.

(5)	Give the userid associated with the application update authority to the alias, but no access to the real dead-letter queue.

NOTE:	If an alias queue is not used in place of the dead-letter queue, then the ACP rules for the dead-letter queue will be coded to restrict unauthorized users and systems from reading the messages on the file.

Undeliverable messages can be routed to a dead-letter queue. Two levels of access should be established for these queues. The first level allows applications, as well as some MQSeries / WebSphere MQ objects, to put messages to this queue. The second level restricts the ability to get messages from this queue and protects sensitive data. This will be accomplished by defining an alias queue that resolves to the real dead-letter queue, but defines the alias queue with the attributes PUT(ENABLED) and GET(DISABLED). The ability to get messages from the dead-letter queue will be restricted to message channel agents (MCAs), CKTI (MQSeries/WebSphere MQ-supplied CICS task initiator), channel initiators utility, and any automated application used for dead-letter queue maintenance.'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27333r868777_chk'
  tag severity: 'medium'
  tag gid: 'V-225632'
  tag rid: 'SV-225632r868779_rule'
  tag stig_id: 'ZWMQ0053'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27321r868778_fix'
  tag 'documentable'
  tag legacy: ['V-6964', 'SV-7267']
  tag cci: ['CCI-001762', 'CCI-000764']
  tag nist: ['CM-7 (1) (b)', 'IA-2']
end
