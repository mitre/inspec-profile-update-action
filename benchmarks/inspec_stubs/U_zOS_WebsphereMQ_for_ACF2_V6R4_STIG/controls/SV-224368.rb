control 'SV-224368' do
  title 'WebSphere MQ context resources defined to the MQADMIN resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists. Some resources provide the ability to disable or bypass security checking. Failure to properly protect WebSphere MQ resources may result in unauthorized access. This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a) Refer to the following report produced by the ACF2 Data Collection:

- SENSITVE.RPT(MQADMIN)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

b) For all context resources (i.e., ssid.CONTEXT) defined to TYPE(MQA) (i.e., MQADMIN resource class, ensure access authorization restricts access to users requiring the ability to pass or set identity and/or origin data for a message. This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

c) If (b) is true, there is no finding.

d) If (b) is untrue, this is a finding.'
  desc 'fix', 'The ISSO will ensure that use of context resources are restricted to authorized personnel.

For all context resources (i.e., ssid.CONTEXT) defined to TYPE(MQA) (i.e., MQADMIN resource class, ensure access authorization restricts access to users requiring the ability to pass or set identity and/or origin data for a message. This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

Example:

$KEY(ssid) TYPE(MQA)
CONTEXT.- UID (CICS SUPPORT) LOG
CONTEXT.- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26045r868269_chk'
  tag severity: 'medium'
  tag gid: 'V-224368'
  tag rid: 'SV-224368r868271_rule'
  tag stig_id: 'ZWMQ0058'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26033r868270_fix'
  tag 'documentable'
  tag legacy: ['SV-7274', 'V-6971']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
