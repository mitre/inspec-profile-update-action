control 'SV-89553' do
  title 'The MQ Appliance messaging server must identify potentially security-relevant error conditions.'
  desc 'The structure and content of error messages need to be carefully considered by the organization and development team. Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system. The extent to which the messaging server is able to identify and handle error conditions is guided by organizational policy and operational requirements. Adequate logging levels and system performance capabilities need to be balanced with data protection requirements.

The structure and content of error messages needs to be carefully considered by the organization and development team.

Messaging servers must have the capability to log at various levels which can provide log entries for potential security-related error events.

An example is the capability for the messaging server to assign a criticality level to a failed logon attempt error message, a security-related error message being of a higher criticality.

Instructions for using the amqsevt sample program to display instrumentation events may be found at the following URL: https://ibm.biz/BdsCzY.

'
  desc 'check', 'Establish an SSH command line session as an admin user.

To access the MQ Appliance CLI, enter:
mqcli
  
To identify the queue managers, enter:
dspmq

Run the "runmqsc [queue mgr name]" command for each running queue manager.  

Once at the runmqsc prompt, enter:

DIS QMGR AUTHOREV
AUTHOREV(ENABLED) - should be the result.

If "AUTHOREV" logging is not "ENABLED", this is a finding.'
  desc 'fix', 'For each queue manager on the MQ Appliance, enable authority (AUTHOREV) event logging.

From the MQ Appliance CLI, enter the following:

runmqsc [queue mgr name]
ALTER QMGR AUTHOREV(ENABLED)
end'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74737r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74879'
  tag rid: 'SV-89553r1_rule'
  tag stig_id: 'MQMH-AS-000450'
  tag gtitle: 'SRG-APP-000266-AS-000168'
  tag fix_id: 'F-81495r1_fix'
  tag satisfies: ['SRG-APP-000266-AS-000168', 'SRG-APP-000091-AS-000052']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-001312']
  tag nist: ['AU-12 c', 'SI-11 a']
end
