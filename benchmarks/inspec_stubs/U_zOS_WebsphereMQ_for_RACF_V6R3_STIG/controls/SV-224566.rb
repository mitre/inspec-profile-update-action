control 'SV-224566' do
  title 'WebSphere MQ command resources defined to MQCMDS resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of  commands.  Failure to properly protect WebSphere MQ Command resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following reports produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(MQCMDS)

b)	For all command resources (i.e., ssid.command) defined to the MQCMDS resource class, ensure the following items are in effect:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Resource profiles are defined with a UACC(NONE).
2)	Access authorization restricts access to the appropriate personnel as designated in the Websphere MQ COMMAND SECURITY CONTROLS Table in the z/OS STIG Addendum.
3)	All command access is logged as designated in the Websphere MQ COMMAND SECURITY CONTROLS Table in the z/OS STIG Addendum.

c)	If all of the items in (b) are true, there is NO FINDING.

d)	If any item in (b) is untrue, this is a FINDING.'
  desc 'fix', %q(Command security validates userids authorized to issue MQSeries / WebSphere MQ commands.  Command security will be active

For all command resources (i.e., ssid.command) defined to the MQCMDS resource class, ensure the following items are in effect:

NOTE 1:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Resource profiles are defined with a UACC(NONE).
2)	Access authorization restricts access to the appropriate personnel as designated in the table entitled "Websphere MQ Command Security Controls " in the zOS STIG Addendum.
3)	All command access is logged as designated in the table entitled "Websphere MQ Command Security Controls" in the zOS STIG Addendum.

A set of sample commands are provided below to implement the minimum profiles necessary for proper security.  

/* THE FOLLOWING PROFILE FORCES GRANULAR PROFILES DEFINITIONS */
RDEF MQCMDS ** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MQCMDS DENY-BY-DEFAULT PROFILE')

RDEF MQCMDSN <ssid>.<CmdName>.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MQCMDS Required See ZWMQ0059')

PE <ssid>.<CmdNAme>.** CL(MQCMDS) ID(<autherizeduser>) ACC(C)

SETR RACL(MQCMDS) REF

Note that an additional WebSphere MQ Refresh may be required for active Qmanagers.  This is done from the CONSOLE:

The example is for a Que Manager Named QMD1
>QMD1 REFRESH SECURITY(*))
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26249r521057_chk'
  tag severity: 'medium'
  tag gid: 'V-224566'
  tag rid: 'SV-224566r521059_rule'
  tag stig_id: 'ZWMQ0059'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26237r521058_fix'
  tag 'documentable'
  tag legacy: ['SV-7554', 'V-6973']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
