control 'SV-224369' do
  title 'WebSphere MQ command resources defined to MQCMDS resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists. Some resources provide the ability to disable or bypass security checking. Failure to properly protect WebSphere MQ resources may result in unauthorized access. This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a) Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(MQCMDS)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

b) For all command resources (i.e., ssid.command) defined to TYPE(MQC) (i.e., MQCMDS resource class, ensure the following items are in effect:

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

1) Access authorization restricts access to the appropriate personnel as designated in the WebSphere MQ COMMAND SECURITY CONTROLS Table in the z/OS STIG Addendum.
2) All command access is logged as designated in the WebSphere MQ COMMAND SECURITY CONTROLS Table in the z/OS STIG Addendum.

c) If both of the items in (b) are true, there is no finding.

d) If either item in (b) is untrue, this is a finding.'
  desc 'fix', "The ISSO will ensure that all MQSeries/WebSphere MQ commands are restricted to authorized personnel.

For all command resources (i.e., ssid.command) defined to TYPE(MQC) (i.e., MQCMDS resource class, ensure the following items are in effect:

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

1) Access authorization restricts access to the appropriate personnel as designated in the table entitled WebSphere MQ COMMAND SECURITY CONTROLS,in the zOS STIG Addendum.

2) All command access is logged as designated in the table entitled WebSphere MQ COMMAND SECURITY CONTROLS, in the zOS STIG Addendum.

Example:

$KEY(ssid) TYPE(MQC)
ALTER.- UID(syspaudt) SERVICE(READ,ADD,UPDATE) LOG
ALTER.- UID(*) PREVENT

SET R(MQC)
COMPILE 'ACF2.MVA.MQC(ssid)' STORE

F ACF2,REBUILD(MQC)"
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26046r868272_chk'
  tag severity: 'medium'
  tag gid: 'V-224369'
  tag rid: 'SV-224369r868274_rule'
  tag stig_id: 'ZWMQ0059'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26034r868273_fix'
  tag 'documentable'
  tag legacy: ['SV-7276', 'V-6973']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
