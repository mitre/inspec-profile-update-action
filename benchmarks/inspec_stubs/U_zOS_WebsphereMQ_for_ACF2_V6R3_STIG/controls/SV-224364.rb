control 'SV-224364' do
  title 'WebSphere MQ queue resource defined to the MQQUEUE resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'Refer to the following report produced by the z/OS Data Collection:

-       MQSRPT(ssid)

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier). 

Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

-	SENSITVE.RPT(MQQUEUE)
-	ACF2CMDS.RPT(RESOURCE) – Alternate report

For all queue identified by the DISPLAY QUEUE(*) ALL command in the MQSRPT(ssid).  These queues will be prefixed by ssid to identify the resources to be protected.  Ensure these queue resources are defined to TYPE(MQQ) (i.e., MQQUEUE resource class) if the following guidance is true, this is not a finding.

1)	For message queues (i.e., ssid.queuename), access authorization restricts access to users requiring the ability to get messages from and put messages to message queues.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list. Decentralized MQ Administrators, non-DECC datacenter users; can have up to ALTER access to the user Message Queues.
2)	For system queues (i.e., ssid.SYSTEM.queuename), access authorization restricts UPDATE and/or  ALTER access to WebSphere MQ STCs, WebSphere MQ administrators, systems programming personnel, and CICS regions running WebSphere MQ applications.
3)	For the following system queues ensure that UPDATE access is restricted to Auditors and Users that require access to review message queues.
ssid.SYSTEM.COMMAND.INPUT
ssid.SYSTEM.COMMAND.REPLY
ssid.SYSTEM.CSQOREXX.*
ssid.SYSTEM.CSQUTIL.*
4)	For the real dead-letter queue (to determine queue name refer to ZWMQ0053), ALTER access authorization restricts access to WebSphere MQ STCs, WebSphere MQ administrators, CICS regions running WebSphere MQ applications, and any automated application used for dead-letter queue maintenance.
5)	For the alias dead-letter queue (to determine queue name refer to ZWMQ0053), UPDATE access authorization restricts access to users requiring the ability to put messages to the dead-letter queue.  This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.'
  desc 'fix', 'The IAO will ensure that all WebSphere MQ queues are restricted using queue level security.

Ensure all queue resources defined to TYPE(MQQ) (i.e., MQQUEUE resource class), are in effect:

For all queue identified by the DISPLAY QUEUE(*) ALL command in the MQSRPT(ssid).  These queues will be prefixed by ssid to identify the resources to be protected.  Ensure these queue resources are defined to TYPE(MQQ) (i.e., MQQUEUE resource class) if the following guidance is true, this is not a finding.

1)	For message queues (i.e., ssid.queuename), access authorization restricts access to users requiring the ability to get messages from and put messages to message queues.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list. Decentralized MQ Administrators, non-DECC datacenter users; can have up to ALTER access to the user Message Queues.
2)	For system queues (i.e., ssid.SYSTEM.queuename), access authorization restricts UPDATE and/or  ALTER access to WebSphere MQ STCs, WebSphere MQ administrators, systems programming personnel, and CICS regions running WebSphere MQ applications.
3)	For the following system queues ensure that UPDATE access is restricted to Auditors and Users that require access to review message queues.
ssid.SYSTEM.COMMAND.INPUT
ssid.SYSTEM.COMMAND.REPLY
ssid.SYSTEM.CSQOREXX.*
ssid.SYSTEM.CSQUTIL.*
4)	For the real dead-letter queue (to determine queue name refer to ZWMQ0053), ALTER access authorization restricts access to WebSphere MQ STCs, WebSphere MQ administrators, CICS regions running WebSphere MQ applications, and any automated application used for dead-letter queue maintenance.
5)	For the alias dead-letter queue (to determine queue name refer to ZWMQ0053), UPDATE access authorization restricts access to users requiring the ability to put messages to the dead-letter queue.  This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.
Example:

$KEY(ssid) TYPE(MQQ)
DEAD.QUEUE UID(STCssidCHIN) SERVICE(READ,UPDATE) LOG
DEAD.QUEUE UID(MQAdministrators) SERVICE(READ,UPDATE) LOG
DEAD.QUEUE UID(*) PREVENT
- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26041r520991_chk'
  tag severity: 'medium'
  tag gid: 'V-224364'
  tag rid: 'SV-224364r520993_rule'
  tag stig_id: 'ZWMQ0054'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26029r520992_fix'
  tag 'documentable'
  tag legacy: ['SV-7268', 'V-6965']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
