control 'SV-224563' do
  title 'WebSphere MQ Namelist resource profiles defined in the MQNLIST Class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following reports produced by the RACF Data Collection:

-	SENSITVE.RPT(MQNLIST)

b)	For all namelist resources (i.e., ssid.namelist) defined to the MQNLIST or GMQNLIST resource classes, ensure the following items are in effect:

NOTE 1:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Resource profiles are defined with a UACC(NONE).
2)	Access authorization restricts access to users requiring the ability to make namelist inquires.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

c)	If both of the items in (b) are true, there is NO FINDING.

d)	If either item in (b) is untrue, this is a FINDING.'
  desc 'fix', "A namelist is a MQSeries / WebSphere MQ object that contains a list of queue names. Namelist security validates userids authorized to inquire on namelists. Namelist security will be active, and all profiles ssid.namelist will be defined to the MQNLIST or GMQNLIST class with UACC(NONE) specified. Restrict read access to those userids requiring access to make namelist inquiries.

For all namelist resources (i.e., ssid.namelist) defined to the MQNLIST or GMQNLIST resource classes, ensure the following items are in effect:

NOTE 1:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Resource profiles are defined with a UACC(NONE).
2)	Access authorization restricts access to users requiring the ability to make namelist inquires.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

A set of sample commands are provided below to implement the minimum profiles necessary for proper security.  

/* THE FOLLOWING PROFILE FORCES GRANULAR PROFILES DEFINITIONS */
RDEF MQNLIST ** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MQCONN DENY-BY-DEFAULT PROFILE')

RDEF MQNLIST <ssid>.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('REQUIRED FOR ZWMQ0056')
PE <ssid>.** CL(MQNLIST) ID(<applicable>)

SETR RACL(MQNLIST) REF

Note that an additional WebSphere MQ Refresh may be required for active Qmanagers.  This is done from the CONSOLE:

The example is for a Que Manager Named QMD1
>QMD1 REFRESH SECURITY(*)"
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26246r521048_chk'
  tag severity: 'medium'
  tag gid: 'V-224563'
  tag rid: 'SV-224563r521050_rule'
  tag stig_id: 'ZWMQ0056'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26234r521049_fix'
  tag 'documentable'
  tag legacy: ['V-6967', 'SV-7548']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
