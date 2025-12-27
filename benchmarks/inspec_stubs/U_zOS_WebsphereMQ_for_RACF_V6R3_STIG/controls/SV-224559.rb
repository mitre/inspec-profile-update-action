control 'SV-224559' do
  title 'WebSphere MQ MQCONN Class (Connection) resource definitions must be protected in accordance with security.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)       Refer to the following reports produced by the RACF Data Collection:

-       SENSITVE.RPT(MQCONN)

b)       Review the following connection resources defined to the MQCONN resource class:

Resource       Authorized Users
ssid.BATCH       TSO and batch job userids
ssid.CICS       CICS region userids
ssid.IMS       IMS region userids
ssid.CHIN       Channel initiator userids

NOTE:       ssid is the queue manager name (a.k.a., subsystem identifier).

c)       For all connection resources defined to the MQCONN resource class, ensure the following items are in effect:

NOTE:       If you do not have a resource profile defined for a particular security check, and a user issues a request that would involve making that check, MQSeries/WebSphere MQ denies access.

1)       Resource profiles are defined with a UACC(NONE).
2)       Access authorization to these connections restricts access to the appropriate users as indicated in (b).
3)       All access FAILUREs are logged.  

d)       If all of the items in (c) are true, there is NO FINDING.

e)       If any item in (c) is untrue, this is a FINDING.'
  desc 'fix', "Review the following connection resources defined to the MQCONN resource class:

Resource       Authorized Users
ssid.BATCH       TSO and batch job userids
ssid.CICS       CICS region userids
ssid.IMS       IMS region userids
ssid.CHIN       Channel initiator userids

NOTE:       ssid is the queue manager name (a.k.a., subsystem identifier).

c)       For all connection resources defined to the MQCONN resource class, ensure the following items are in effect:

NOTE:       If you do not have a resource profile defined for a particular security check, and a user issues a request that would involve making that check, MQSeries/WebSphere MQ denies access.

1)       Resource profiles are defined with a UACC(NONE).
2)       Access authorization to these connections restricts access to the appropriate users as indicated in (b).
3)       All access FAILUREs are logged.

A set of sample commands are provided below to implement the minimum profiles necessary for proper security. Note that the IMS and/or CICS profiles can be omitted if those products do not run on the target system.

/* THE FOLLOWING PROFILE FORCES GRANULAR PROFILES DEFINITIONS */
RDEF MQCONN ** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURES(READ)) DATA('MQCONN DENY-BY-DEFAULT PROFILE')

RDEF MQCONN <ssid>.BATCH UACC(NONE) OWNER(ADMIN) AUDIT(FAILURES(READAUDIT(FAILURES(READ)) DATA('REQUIRED FOR ZWMQ0052')
PE <ssid>.BATCH CL(MQCONN) ID(<applicableTSO&batchUsers>)

RDEF MQCONN <ssid>.CICS UACC(NONE) OWNER(ADMIN) AUDIT(FAILURES(READ)) DATA('REQUIRED FOR ZWMQ0052')
PE <ssid>.CICS CL(MQCONN) ID(<CICSRegionUserids>)

RDEF MQCONN <ssid>.IMS UACC(NONE) OWNER(ADMIN) AUDIT(FAILURES(READ)) DATA('REQUIRED FOR ZWMQ0052')
PE <ssid>.IMS CL(MQCONN) ID(<IMSRegionUserids>)

RDEF MQCONN <ssid>.CHIN UACC(NONE) OWNER(ADMIN) AUDIT(FAILURES(READ)) DATA('REQUIRED FOR ZWMQ0052')
PE <ssid>.CHIN CL(MQCONN) ID(<WebsphereMQCHINUsrids>)

SETR RACL(MQCONN) REF

Note that an additional WebSphere MQ Refresh may be required for active Qmanagers. This is done from the CONSOLE:

The example is for a Que Manager Named QMD1
>QMD1 REFRESH SECURITY(*)"
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26242r521036_chk'
  tag severity: 'medium'
  tag gid: 'V-224559'
  tag rid: 'SV-224559r521038_rule'
  tag stig_id: 'ZWMQ0052'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26230r521037_fix'
  tag 'documentable'
  tag legacy: ['V-6962', 'SV-7541']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
