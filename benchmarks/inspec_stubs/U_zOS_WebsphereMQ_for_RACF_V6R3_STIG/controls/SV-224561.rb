control 'SV-224561' do
  title 'WebSphere MQ MQQUEUE (Queue) resource profiles defined to the MQQUEUE class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'Refer to the following report produced by the z/OS Data Collection:

-       MQSRPT(ssid)

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier). 

Refer to the following reports produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(MQQUEUE)

For all queue identified by the DISPLAY QUEUE(*) ALL command in the MQSRPT(ssid).  These queues will be prefixed by ssid to identify the resources to be protected.  Ensure these queue resources are defined to the MQQUEUE or GMQQUEUE resource classes, ensure the following items are in effect:

1)	Resource profiles are defined with a UACC(NONE).
2)	For message queues (i.e., ssid.queuename), access authorization restricts access to users requiring the ability to get messages from and put messages to message queues.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.
3)	For system queues (i.e., ssid.SYSTEM.queuename), ALTER access authorization restricts access to WebSphere MQ STCs, WebSphere MQ administrators, systems programming personnel, and CICS regions running WebSphere MQ applications.
4)	For the following system queues ensure that UPDATE access is restricted to WebSphere MQ STCs, WebSphere MQ administrators, systems programming personnel, CICS regions running WebSphere MQ applications, auditors, and users that require access to review message queues.
ssid.SYSTEM.COMMAND.INPUT
ssid.SYSTEM.COMMAND.REPLY
ssid.SYSTEM.CSQOREXX.*
5)	For system queues (i.e., ssid.SYSTEM.CSQUTIL.*) ensure that UPDATE access is restricted to WebSphere MQ STCs, WebSphere MQ administrators, systems programming personnel, CICS regions running WebSphere MQ applications, and auditors.
6)	For the real dead-letter queue (to determine queue name refer to ZWMQ0053), ALTER access authorization restricts access to WebSphere MQ STCs, WebSphere MQ administrators, CICS regions running WebSphere MQ applications, and any automated application used for dead-letter queue maintenance.
7)	For the alias dead-letter queue (to determine queue name refer to ZWMQ0053), UPDATE access authorization restricts access to users requiring the ability to put messages to the dead-letter queue.  This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.'
  desc 'fix', "For all queue resources defined to the MQQUEUE or GMQQUEUE resource classes, ensure the following items are in effect:

For all queue identified by the DISPLAY QUEUE(*) ALL command in the MQSRPT(ssid).  These queues will be prefixed by ssid to identify the resources to be protected.  Ensure these queue resources are defined to the MQQUEUE or GMQQUEUE resource classes, if the following guidance is true, this is not a finding.

1)	Resource profiles are defined with a UACC(NONE).
2)	For message queues (i.e., ssid.queuename), access authorization restricts access to users requiring the ability to get messages from and put messages to message queues.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list. Decentralized MQ Administrators, non-DECC datacenter users; can have up to ALTER access to the user Message Queues.
3)	For system queues (i.e., ssid.SYSTEM.queuename), access authorization restricts UPDATE and/or  ALTER access to WebSphere MQ STCs, WebSphere MQ administrators, systems programming personnel, and CICS regions running WebSphere MQ applications.
4)	For the following system queues ensure that UPDATE access is restricted to Auditors and Users that require access to review message queues.
ssid.SYSTEM.COMMAND.INPUT
ssid.SYSTEM.COMMAND.REPLY
ssid.SYSTEM.CSQOREXX.*
ssid.SYSTEM.CSQUTIL.*
5)	For the real dead-letter queue (to determine queue name refer to ZWMQ0053), ALTER access authorization restricts access to WebSphere MQ STCs, WebSphere MQ administrators, CICS regions running WebSphere MQ applications, and any automated application used for dead-letter queue maintenance.
6)	For the alias dead-letter queue (to determine queue name refer to ZWMQ0053), UPDATE access authorization restricts access to users requiring the ability to put messages to the dead-letter queue.  This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.

Example:

RDEF MQQUEUE <ssid>.SYSTEM.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ)) DATA('REQUIRED FOR ZWMQ0054')
PE <ssid>.SYSTEM.** CL(MQQUEUE) ID(<RestrictedUsersAsSpecifiecAbove>)

RDEF MQQUEUE <ssid>.<qname>.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ)) DATA('REQUIRED FOR ZWMQ0054')
PE <ssid>.<qname> CL(MQQUEUE) ID(<AsSpecifiedAbove>)

RDEF MQQUEUE <ssid>.<RealDeadLetterQue>.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ)) DATA('REQUIRED FOR ZWMQ0054')
PE <ssid>.<RealDeadLetterQue> CL(MQQUEUE) ID(<AsSpecifiedAbove>)

RDEF MQQUEUE <ssid>.<AliasDeadLetterQue>.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ)) DATA('REQUIRED FOR ZWMQ0054')
PE <ssid>.<AliasDeadLetterQue> CL(MQQUEUE) ID(<AsSpecifiedAbove>)

SETR RACL(MQQUEUE) REF"
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26244r521042_chk'
  tag severity: 'medium'
  tag gid: 'V-224561'
  tag rid: 'SV-224561r521044_rule'
  tag stig_id: 'ZWMQ0054'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26232r521043_fix'
  tag 'documentable'
  tag legacy: ['V-6965', 'SV-7544']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
