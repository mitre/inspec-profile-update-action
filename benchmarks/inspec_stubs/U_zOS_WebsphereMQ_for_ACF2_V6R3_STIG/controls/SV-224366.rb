control 'SV-224366' do
  title 'WebSphere MQ Namelist resources are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the ACF2 Data Collection:

-	SENSITVE.RPT(MQNLIST)
-	ACF2CMDS.RPT(RESOURCE) – Alternate report

b)	For all namelist resources (i.e., ssid.namelist) defined to TYPE(MQN) (i.e., MQNLIST resource class), ensure access authorization restricts access to users requiring the ability to make namelist inquiries.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

c)	If (b) is true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that all MQSeries/WebSphere MQ namelist resources are restricted to authorized users.

For all namelist resources (i.e., ssid.namelist) defined to TYPE(MQN) (i.e., MQNLIST resource class), ensure access authorization restricts access to users requiring the ability to make namelist inquiries.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

Example:

$KEY(QZN1) TYPE(MQN)
SYSTEM.DEFAULT.NAMELIST UID(MQAdministrators) SERVICE(READ) LOG
SYSTEM.DEFAULT.NAMELIST UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26043r520997_chk'
  tag severity: 'medium'
  tag gid: 'V-224366'
  tag rid: 'SV-224366r520999_rule'
  tag stig_id: 'ZWMQ0056'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26031r520998_fix'
  tag 'documentable'
  tag legacy: ['SV-7270', 'V-6967']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
