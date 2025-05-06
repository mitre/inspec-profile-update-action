control 'SV-224362' do
  title 'WebSphere MQ MQCONN Class resources must be protected in accordance with security.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists. Some resources provide the ability to disable or bypass security checking. Failure to properly protect WebSphere MQ resources may result in unauthorized access. This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a) Refer to the following report produced by the ACF2 Data Collection:

- SENSITVE.RPT(MQCONN)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

b) Review the following connection resources defined to TYPE(MQK) (i.e., MQCONN resource class):

Resource         Authorized Users
ssid.BATCH     TSO and batch job userids
ssid.CICS         CICS region userids
ssid.IMS          IMS region userids
ssid.CHIN        Channel initiator userids

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

c) For all connection resources defined to TYPE(MQK), ensure the following items are in effect:

1) Access authorization to these connections restricts access to the appropriate users as indicated in (b).
2) All access FAILUREs are logged.

d) If both of the items in (c) are true, there is no finding.

e) If either item in (c) is untrue, this is a finding.'
  desc 'fix', 'Ensure all connections to MQSeries/WebSphere MQ resources are restricted using connection security.

Ensure the following connection resources defined to TYPE(MQK) (i.e., MQCONN resource class):

Resource       Authorized Users
ssid.BATCH       TSO and batch job userids
ssid.CICS       CICS region userids
ssid.IMS       IMS region userids
ssid.CHIN       Channel initiator userids

NOTE:       ssid is the queue manager name (a.k.a., subsystem identifier).

For all connection resources defined to TYPE(MQK), ensure the following items are in effect:

Access authorization to these connections restricts access to the appropriate users as indicated above.

All access FAILURE is logged.

Example:

$KEY(ssid) TYPE(MQK)
BATCH UID(STCssid) SERVICE(READ)  
BATCH UID(syspaudt) SERVICE(READ)  
BATCH UID(*) PREVENT 
CHIN UID(STCssidCHIN) SERVICE(READ)  
CHIN UID(*) PREVENT 
CICS UID(*) PREVENT 
IMS UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26039r868251_chk'
  tag severity: 'medium'
  tag gid: 'V-224362'
  tag rid: 'SV-224362r868253_rule'
  tag stig_id: 'ZWMQ0052'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26027r868252_fix'
  tag 'documentable'
  tag legacy: ['V-6962', 'SV-7263']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
