control 'SV-225630' do
  title 'Websphere MQ switch profiles must be properly defined to the MQADMIN class.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a) Refer to the following report produced by the z/OS Data Collection:

-       MQSRPT(ssid)

NOTE:       ssid is the queue manager name (a.k.a., subsystem identifier).

Automated Analysis requires Additional Analysis.
Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-       PDI(ZWMQ0051)

b) Review the Security switches identified in response to the DISPLAY SECURITY command in each ssid report(s).       If the all of the following switches specify ON, there is NO FINDING.

SUBSYSTEM
CONNECTION
COMMAND
CONTEXT
ALTERNATE USER
PROCESS
NAMELIST
QUEUE
COMMAND RESOURCES

c) If SUBSYSTEM specifies OFF, this is a FINDING with a severity of Category I.

d) If any of the other above switches specify OFF (other than the exception mentioned below), this is a FINDING downgrade the severity to a Category II.

e) If COMMAND RESOURCE Security switch specify OFF, there is NO FINDING.

NOTE:       At the discretion of the IAO, COMMAND RESOURCE Security switch may specify OFF, by defining ssid.NO.CMD.RESC.CHECKS in the MQADMIN resource class.'
  desc 'fix', 'Switch profiles are special WebSphere MQ profiles that are used to turn on/off security checking for a type of resource.  Due to the security exposure this creates, no profiles with the first two qualifiers of ssid.NO will be defined to the MQADMIN class, with one exception.  Due to the fact that (1) all sensitive WebSphere MQ commands are restricted to queue managers, channel initiators, and designated systems personnel, and (2) no command resource checking is performed on DISPLAY commands, at the discretion of the IAO a ssid.NO.CMD.RESC.CHECKS switch profile may be defined to the MQADMIN class. 1. Identify if any switch profile permissions exist using the sample TSS command: TSS WHOHAS MQADMIN(ssid.NO) 2. Use the "TSS REVOKE(acid) MQADMIN(ssid.NO)" to revoke the permission.'
  impact 0.7
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27331r472692_chk'
  tag severity: 'high'
  tag gid: 'V-225630'
  tag rid: 'SV-225630r472694_rule'
  tag stig_id: 'ZWMQ0051'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27319r472693_fix'
  tag 'documentable'
  tag legacy: ['V-6960', 'SV-7539']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
