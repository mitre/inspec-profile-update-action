control 'SV-224365' do
  title 'WebSphere MQ Process resources are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the ACF2 Data Collection:

-	SENSITVE.RPT(MQPROC)
-	ACF2CMDS.RPT(RESOURCE) – Alternate report

b)	For all process resources (i.e., ssid.processname) defined to TYPE(MQP) (i.e., MQPROC resource class), ensure access authorization restricts access to users requiring the ability to make process inquiries.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

c)	If (b) is true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that process security is active, and that all profiles defined to the MQPROC class and that process inquiries are restricted to read access.

For all process resources (i.e., ssid.processname) defined to TYPE(MQP) (i.e., MQPROC resource class), ensure access authorization restricts access to users requiring the ability to make process inquiries.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

Example:

$KEY(ssid) TYPE(MQP)
CHL_TRIG_PROCESS UID(MQAdministrators) SERVICE(READ) LOG 
CHL_TRIG_PROCESS UID(*) PREVENT
SYSTEM.DEFAULT.PROCESS UID(MQAdministrators) SERVICE(READ) LOG
SYSTEM.DEFAULT.PROCESS UID(*)  PREVENT'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26042r520994_chk'
  tag severity: 'medium'
  tag gid: 'V-224365'
  tag rid: 'SV-224365r520996_rule'
  tag stig_id: 'ZWMQ0055'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26030r520995_fix'
  tag 'documentable'
  tag legacy: ['V-6966', 'SV-7269']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
