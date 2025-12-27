control 'SV-224358' do
  title 'WebSphere MQ started tasks are not defined in accordance with the proper security requirements.'
  desc 'Started tasks are used to execute WebSphere MQ queue manager services.  Improperly defined WebSphere MQ started tasks may result in inappropriate access to application resources and the loss of accountability.  This exposure could compromise the availability of some system services and application data.'
  desc 'check', 'a)	Refer to the following reports produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(LOGONIDS)
-	ACF2CMDS.RPT(ATTSTC)

Provide a list of all WebSphere MQ Subsystem Ids (Queue managers) and Release levels.

b)	Review WebSphere MQ started tasks and ensure the following items are in effect:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).
ssidMSTR is the name of a queue manager STC.
ssidCHIN is the name of a distributed queuing (a.k.a., channel initiator) STC.

1)	Each ssidMSTR and ssidCHIN started task is associated with a unique logonid.
2)	Each ssidMSTR and ssidCHIN STC logonid has the attributes of STC, MUSASS, and NOSMC.

c)	If both of the items in (b) are true, there is NO FINDING.

d)	If either item in (b) is untrue, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that all MQSeries/WebSphere MQ started tasks are properly defined.

Review MQSeries/WebSphere MQ started tasks and ensure the following items are in effect:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).
ssidMSTR is the name of a queue manager STC.
ssidCHIN is the name of a distributed queuing (a.k.a., channel initiator) STC.

1)	Each MQSeries/WebSphere MQ started task is associated with a unique logonid.

2)	Each MQSeries/WebSphere MQ STC logonid has the attributes of STC, MUSASS, and NOSMC.

Example:

SET LID 
INSERT ssid.MSTR NAME(MQseries, STC) STC MUSASS NO-SMC

INSERT ssid.CHIN NAME(MQseries, STC) STC MUSASS NO-SMC'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26035r520973_chk'
  tag severity: 'medium'
  tag gid: 'V-224358'
  tag rid: 'SV-224358r520975_rule'
  tag stig_id: 'ZWMQ0030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26023r520974_fix'
  tag 'documentable'
  tag legacy: ['SV-3904', 'V-3904']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
