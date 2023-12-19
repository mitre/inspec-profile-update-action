control 'SV-224360' do
  title 'WebSphere MQ resource classes are not properly activated.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(ACFGSO)

Ensure the System Authorization Facility Definition (SAFDEF) include an entry for WebSphere MQ as follows:

INSERT SAFDEF.MQS ID(MQS) FUNCRET(8) RETCODE(4) MODE(IGNORE)
RACROUTE(REQUEST=EXTRACT,CLASS=MQADMIN) REP

Ensure the Internal CLASMAP Definitions include the following entries:

INSERT CLASMAP.MQADMIN RESOURCE(MQADMIN) RSRCTYPE(MQA) ENTITYLN(62)
INSERT CLASMAP.MQCMDS RESOURCE(MQCMDS) RSRCTYPE(MQC) ENTITYLN(22)
INSERT CLASMAP.MQCONN RESOURCE(MQCONN) RSRCTYPE(MQK) ENTITYLN(10)
INSERT CLASMAP.MQNLIST RESOURCE(MQNLIST) RSRCTYPE(MQN) ENTITYLN(53)
INSERT CLASMAP.MQPROC RESOURCE(MQPROC) RSRCTYPE(MQP) ENTITYLN(53)
INSERT CLASMAP.MQQUEUE RESOURCE(MQQUEUE) RSRCTYPE(MQQ) ENTITYLN(53)

For V7.0.0 and above:

INSERT CLASMAP.MXADMIN RESOURCE(MXADMIN) RSRCTYPE(MXA) ENTITYLN(62)
INSERT CLASMAP.MXNLIST RESOURCE(MXNLIST) RSRCTYPE(MXN) ENTITYLN(53)
INSERT CLASMAP.MXPROC RESOURCE(MXPROC) RSRCTYPE(MXP) ENTITYLN(53)
INSERT CLASMAP.MXQUEUE RESOURCE(MXQUEUE) RSRCTYPE(MXQ) ENTITYLN(53)
INSERT CLASMAP.MXTOPIC RESOURCE(MXTOPIC) RSRCTYPE(MXT) ENTITYLN(246)'
  desc 'fix', 'The IAO will ensure that all WebSphere MQ resources are active and properly defined.

Ensure the System Authorization Facility Definition (SAFDEF) include an entry for WebSphere MQ as follows:

INSERT SAFDEF.MQS ID(MQS) FUNCRET(8) RETCODE(4) MODE(IGNORE)
RACROUTE(REQUEST=EXTRACT,CLASS=MQADMIN) REP

Ensure the Internal CLASMAP Definitions include the following entries:

INSERT CLASMAP.MQADMIN RESOURCE(MQADMIN) RSRCTYPE(MQA) ENTITYLN(62)
INSERT CLASMAP.MQQUEUE RESOURCE(MQQUEUE) RSRCTYPE(MQQ) ENTITYLN(53)
INSERT CLASMAP.MQNLIST RESOURCE(MQNLIST) RSRCTYPE(MQN) ENTITYLN(53)
INSERT CLASMAP.MQCMDS RESOURCE(MQCMDS) RSRCTYPE(MQC) ENTITYLN(22)
INSERT CLASMAP.MQCONN RESOURCE(MQCONN) RSRCTYPE(MQK) ENTITYLN(10)
INSERT CLASMAP.MQPROC RESOURCE(MQPROC) RSRCTYPE(MQP) ENTITYLN(53)

For V7.0.0 and above:

INSERT CLASMAP.MXADMIN RESOURCE(MXADMIN) RSRCTYPE(MXA) ENTITYLN(62)
INSERT CLASMAP.MXNLIST RESOURCE(MXNLIST) RSRCTYPE(MXN) ENTITYLN(53)
INSERT CLASMAP.MXPROC RESOURCE(MXPROC) RSRCTYPE(MXP) ENTITYLN(53)
INSERT CLASMAP.MXQUEUE RESOURCE(MXQUEUE) RSRCTYPE(MXQ) ENTITYLN(53)
INSERT CLASMAP.MXTOPIC RESOURCE(MXTOPIC) RSRCTYPE(MXT) ENTITYLN(246)'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26037r520979_chk'
  tag severity: 'medium'
  tag gid: 'V-224360'
  tag rid: 'SV-224360r855236_rule'
  tag stig_id: 'ZWMQ0049'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26025r520980_fix'
  tag 'documentable'
  tag legacy: ['V-6959', 'SV-7260']
  tag cci: ['CCI-000213', 'CCI-002358']
  tag nist: ['AC-3', 'AC-25']
end
