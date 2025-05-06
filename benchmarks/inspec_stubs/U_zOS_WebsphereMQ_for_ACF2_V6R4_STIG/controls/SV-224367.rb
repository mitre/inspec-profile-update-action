control 'SV-224367' do
  title 'WebSphere MQ alternate user resources defined to MQADMIN resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists. Some resources provide the ability to disable or bypass security checking. Failure to properly protect WebSphere MQ resources may result in unauthorized access. This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a) Refer to the following report produced by the ACF2 Data Collection:

- SENSITVE.RPT(MQADMIN)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

b) For all alternate user resources (i.e., ssid.ALTERNATE.USER.alternatelogonid) defined to TYPE(MQA) (i.e., MQADMIN resource class), ensure access authorization restricts access to users requiring the ability to use the alternate userid. This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

c) If (b) is true, there is no finding.

d) If (b) is untrue, this is a finding.'
  desc 'fix', 'The ISSO will ensure that use of alternate userids is restricted to authorized personnel.

For all alternate user resources (i.e., ssid.ALTERNATE.USER.alternatelogonid) defined to TYPE(MQA) (i.e., MQADMIN resource class), ensure access authorization restricts access to users requiring the ability to use the alternate userid. This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

Example:

$KEY(ssid) TYPE(MQA)
ALTERNATE.USER.- UID(CICS support) SERVICE(READ,UPDATE) LOG 
ALTERNATE.USER.- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26044r868266_chk'
  tag severity: 'medium'
  tag gid: 'V-224367'
  tag rid: 'SV-224367r868268_rule'
  tag stig_id: 'ZWMQ0057'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26032r868267_fix'
  tag 'documentable'
  tag legacy: ['SV-7272', 'V-6969']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
