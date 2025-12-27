control 'SV-224556' do
  title 'WebSphere MQ all update and alter access to MQSeries/WebSphere MQ product and system data sets are not properly restricted'
  desc 'MVS data sets provide the configuration, operational, and executable properties of WebSphere MQ.  Some data sets are responsible for the security implementation of WebSphere MQ.  Failure to properly protect these data sets may lead to unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the ACP Data Collection:

-	SENSITVE.RPT(MQSRPT)

b)	Ensure ACP data sets rules for MQSeries/WebSphere MQ system data sets (e.g., SYS2.MQM.) restrict access as follows:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

___	READ access to data sets referenced by the following DDnames is restricted to MQSeries/WebSphere MQ STCs, MQSeries/WebSphere MQ administrators, and system programming personnel. All access to these data sets is logged.

DDname	Procedure	Description
CSQINP1	ssidMSTR	Input parameters
CSQINP2	ssidMSTR	Input parameters
CSQXLIB	ssidCHIN	User exit library

NOTE:	WRITE/UPDATE and/or ALLOCATE/ALTER access to these data sets is restricted to MQSeries/WebSphere MQ administrators and systems programming personnel.

___	WRITE/UPDATE and/or ALLOCATE/ALTER access to data sets referenced by the following DDnames is restricted to MQSeries/WebSphere MQ STCs, MQSeries/WebSphere MQ administrators, and systems programming personnel.  All WRITE and ALLOCATE access to these data sets is logged.

DDname	Procedure	Description
CSQPxxxx	ssidMSTR	Page data sets
BSDSx	ssidMSTR	Bootstrap data sets
CSQOUTx	ssidMSTR	SYSOUT data sets
CSQSNAP	ssidMSTR	DUMP data set
(See note)	ssidMSTR	Log data sets

NOTE:	To determine the log data set names, review the JESMSGLG file of the ssidMSTR active task(s).  Find CSQJ001I messages to obtain DSNs.

 
___	ALLOCATE/ALTER access to archive data sets is restricted to MQSeries/WebSphere MQ STCs, MQSeries/WebSphere MQ administrator, and system programming personnel.  All ALLOCATE/ALTER access to these data sets is logged.

NOTE:	To determine the archive data sets names, review the JESMSGLG file of the ssidMSTR active task(s).  Find the CSQY122I message to obtain the ARCPRFX1 and ARCPRFX2 DSN HLQs.

___	Except for the specific data set requirements just mentioned, WRITE/UPDATE and/or ALLOCATE/ALTER access to all other MQSeries/WebSphere MQ system data sets is restricted to the MQSeries/WebSphere MQ administrator and system programming personnel.

c)	If all the items in (b) are true, there is NO FINDING.

d)	If any item in (b) is untrue, this is a FINDING.'
  desc 'fix', 'The systems programmer will have the IAO  ensure that all update and alter access to MQSeries/WebSphere MQ product and system data sets are restricted to WebSphere MQ administrators, systems programmers, and MQSeries/WebSphere MQ started tasks.

The installation requires that the following data sets be APF authorized.  

hlqual.SCSQAUTH
hlqual.SCSQLINK
hlqual.SCSQANLx
hlqual.SCSQSNL
hlqual.SCSQMVR1
hlqual.SCSQMVR2

(2)	Read access to data sets referenced by the CSQINP1, CSQINP2, and CSQXLIB DDs in the queue manager’s procedure will be restricted to the queue manager userid, WebSphere MQ administrator, and systems programming personnel.  Log all access to these data sets.

(3)	Write and allocate access to data set profiles protecting all page sets, logs, bootstrap data sets (BSDS), and data sets referenced by the CSQOUTX and CSQSNAP DDs in the queue manager’s procedure will be restricted to the queue manager userid, WebSphere MQ administrator, and systems programming personnel.  Log all write and allocate access to these data sets.

(5)	Allocate access to all archive data sets in the queue manager’s procedure will be restricted to the queue manager userid, WebSphere MQ administrator, and systems programming personnel.  Log all allocate access to these data sets.'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26239r521027_chk'
  tag severity: 'medium'
  tag gid: 'V-224556'
  tag rid: 'SV-224556r521029_rule'
  tag stig_id: 'ZWMQ0040'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26227r521028_fix'
  tag 'documentable'
  tag legacy: ['SV-3905', 'V-3905']
  tag cci: ['CCI-001499', 'CCI-002234', 'CCI-000213']
  tag nist: ['CM-5 (6)', 'AC-6 (9)', 'AC-3']
end
