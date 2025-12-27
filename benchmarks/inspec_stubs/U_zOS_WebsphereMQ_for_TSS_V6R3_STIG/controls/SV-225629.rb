control 'SV-225629' do
  title 'WebSphere MQ security class(es) is(are) defined improperly.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#RDT)
-	TSSCMDS.RPT(WHOOMADM)
-	TSSCMDS.RPT(WHOOMCMD)
-	TSSCMDS.RPT(WHOOMCON)
-	TSSCMDS.RPT(WHOOMNLI)
-	TSSCMDS.RPT(WHOOMPRO)
-	TSSCMDS.RPT(WHOOMQUE)
-	TSSCMDS.RPT(WHOOXADM)
-	TSSCMDS.RPT(WHOOXNLI)
-	TSSCMDS.RPT(WHOOXPRO)
-	TSSCMDS.RPT(WHOOXQUE)
-	TSSCMDS.RPT(WHOOXTOP)

Ensure the following WebSphere MQ resource classes are defined to the TSS RDT:

MQADMIN
MQCONN
MQCMDS
MQNLIST
MQPROC
MQQUEUE

For V7.0.0 and above:

MXADMIN
MXNLIST
MXPROC
MXQUEUE
MXTOPIC

Ensure that each ssid. resource is defined in each of the above resource classes.

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

NOTE:	If both MQADMIN and MXADMIN resource classes are not defined to the RDT record, no security checking is performed.'
  desc 'fix', 'The IAO will ensure that all WebSphere MQ resources are defined to TSS.

The following should be defined to the RDT:

MQADMIN
MQCONN
MQCMDS
MQNLIST
MQPROC
MQQUEUE

For V7.0.0 and above:

MXADMIN
MXNLIST
MXPROC
MXQUEUE
MXTOPIC

Use the following commands to define (establish ownership of) resources for each WebSphere MQ subsystem to TSS:

TSS ADD(deptname) MQADMIN(ssid.)
TSS ADD(deptname) MQCMDS(ssid.)
TSS ADD(deptname) MQCONN(ssid.)
TSS ADD(deptname) MQNLIST(ssid.)
TSS ADD(deptname) MQPROC(ssid.)
TSS ADD(deptname) MQQUEUE(ssid.)

For V7.0.0 and above:

TSS ADD(deptname) MXADMIN(ssid.)
TSS ADD(deptname) MXNLIST(ssid.)
TSS ADD(deptname) MXPROC(ssid.)
TSS ADD(deptname) MXQUEUE(ssid.)
TSS ADD(deptname) MXTOPIC(ssid.)

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

Another method to ensure protection is to assign the DEFPROT attribute to the resource class in the RDT record by using the following command:

TSS REP(RDT) RESCLASS(MQADMIN) ATTR(DEFPROT)
TSS REP(RDT) RESCLASS(MQCMDS) ATTR(DEFPROT)
TSS REP(RDT) RESCLASS(MQCONN) ATTR(DEFPROT)
TSS REP(RDT) RESCLASS(MQNLIST) ATTR(DEFPROT)
TSS REP(RDT) RESCLASS(MQPROC) ATTR(DEFPROT)
TSS REP(RDT) RESCLASS(MQQUEUE) ATTR(DEFPROT)

For V7.0.0 and above:

TSS REP(RDT) RESCLASS(MXADMIN) ATTR(DEFPROT)
TSS REP(RDT) RESCLASS(MXNLIST) ATTR(DEFPROT)
TSS REP(RDT) RESCLASS(MXPROC) ATTR(DEFPROT)
TSS REP(RDT) RESCLASS(MXQUEUE) ATTR(DEFPROT)
TSS REP(RDT) RESCLASS(MXTOPIC) ATTR(DEFPROT)'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27330r472689_chk'
  tag severity: 'medium'
  tag gid: 'V-225629'
  tag rid: 'SV-225629r472691_rule'
  tag stig_id: 'ZWMQ0049'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27318r472690_fix'
  tag 'documentable'
  tag legacy: ['SV-7535', 'V-6959']
  tag cci: ['CCI-000213', 'CCI-002358']
  tag nist: ['AC-3', 'AC-25']
end
