control 'SV-224555' do
  title 'WebSphere MQ started tasks are not defined in accordance with the proper security requirements.'
  desc 'Started tasks are used to execute WebSphere MQ queue manager services.  Improperly defined WebSphere MQ started tasks may result in inappropriate access to application resources and the loss of accountability.  This exposure could compromise the availability of some system services and application data.'
  desc 'check', 'a)	Refer to the following reports produced by the RACF Data Collection:

-	DSMON.RPT(RACSPT)
-	RACFCMDS.RPT(LISTUSER)

Provide a list of all WebSphere MQ Subsystem Ids (Queue managers) and Release levels.

b)	Review WebSphere MQ started tasks and ensure the following items are in effect:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).
ssidMSTR is the name of a queue manager STC.
ssidCHIN is the name of a distributed queuing (a.k.a., channel initiator) STC.

1)	Each ssidMSTR and ssidCHIN started task is associated with a unique userid.
2)	All ssidMSTR and ssidCHIN started tasks are defined to the STARTED resource class.
3)	All ssidMSTR and ssidCHIN started tasks userid are defined as a PROTECTED.

c)	If both of the items in (b) are true, there is NO FINDING.

d)	If either item in (b) is untrue, this is a FINDING.'
  desc 'fix', %q(Each queue manager started task procedure xxxxMSTR and distributed queuing started task procedure xxxxCHIN will have a matching profile defined to the STARTED resource class.  Create a corresponding userid for each started task. The STC userids will be defined as PROTECTED userids. Queue manager and channel initiator started tasks will not be defined with the TRUSTED attribute.

The following sample contains commands to properly define the required Started Procs:

Note that this example uses "qmq1" as the value for ssid.

AU qmq1mstr NAME('STC, MQSERIES') NOPASS DFLTGRP(STC) OWNER(STC) DATA('MQSERIES QUEUE MANAGER PROC')      
                
AU qmq1chin NAME('STC, MQSERIES') NOPASSDFLTGRP(STC) OWNER(STC) DATA('MQSERIES DISTRIBUTED QUEUING CHANNEL INIT PROC')   

RDEF STARTED qmq1mstr.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MAP qmq1mstr PROC TO qmq1mstr USERID') STDATA(USER(=MEMBER) GROUP(STC) TRACE(YES))

RDEF STARTED qmq1chin.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MAP qmq1mstr PROC TO qmq1chin USERID') STDATA(USER(=MEMBER) GROUP(STC) TRACE(YES))

SETR RACL(STARTED) REFRESH)
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26238r521024_chk'
  tag severity: 'medium'
  tag gid: 'V-224555'
  tag rid: 'SV-224555r521026_rule'
  tag stig_id: 'ZWMQ0030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26226r521025_fix'
  tag 'documentable'
  tag legacy: ['SV-7526', 'V-3904']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
