control 'SV-224370' do
  title 'WebSphere MQ RESLEVEL resources in the MQADMIN resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

-	SENSITVE.RPT(MQADMIN)
-	ACF2CMDS.RPT(RESOURCE) – Alternate report

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZWMQ0060)

b)	Ensure the following items are in effect:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	A RESLEVEL resource (i.e., ssid.RESLEVEL) is defined for each queue manager to TYPE(MQA) (i.e., MQADMIN resource class) with a default access of PREVENT.
2)	Access authorization to these RESLEVEL resources restricts all access.  No users are permitted access to ssid.RESLEVEL resources.

c)	If both of the items in (b) are true, there is NO FINDING.

d)	If either item in (b) is untrue, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that a ssid.RESLEVEL profile is only defined for each queue manager.

Ensure the following items are in effect:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	A RESLEVEL resource (i.e., ssid.RESLEVEL) is defined for each queue manager to TYPE(MQA) (i.e., MQADMIN resource class) with a default access of PREVENT.
2)	Access authorization to these RESLEVEL resources restricts all access.  No users are permitted access to ssid.RESLEVEL resources.

Example:

$KEY(ssid) TYPE(MQA)
RESLEVEL UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26047r521009_chk'
  tag severity: 'medium'
  tag gid: 'V-224370'
  tag rid: 'SV-224370r521011_rule'
  tag stig_id: 'ZWMQ0060'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26035r521010_fix'
  tag 'documentable'
  tag legacy: ['V-6975', 'SV-7278']
  tag cci: ['CCI-001762', 'CCI-000213']
  tag nist: ['CM-7 (1) (b)', 'AC-3']
end
