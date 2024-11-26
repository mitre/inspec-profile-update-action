control 'SV-224562' do
  title 'WebSphere MQ Process resource profiles defined in the MQPROC Class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ Process resources allow for the control of processes.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following reports produced by the RACF Data Collection:

-	SENSITVE.RPT(MQPROC)

b)	For all process resources (i.e., ssid.processname) defined to the MQPROC or GMQPROC resource classes, ensure the following items are in effect:

NOTE 1:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Resource profiles are defined with a UACC(NONE).
2)	Access authorization restricts access to users requiring the ability to make process inquires.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

c)	If both of the items in (b) are true, there is NO FINDING.

d)	If either item in (b) is untrue, this is a FINDING.'
  desc 'fix', "Process security validates userids authorized to issue MQSeries / WebSphere MQ inquiries on process definitions. A process definition object defines an application that is started in response to a trigger event on a queue manager. Process security will be active, and all profiles
ssid.processname will be defined to the MQPROC class. Restrict read access to those userids requiring access to make process inquiries.

For all process resources (i.e., ssid.processname) defined to the MQPROC or GMQPROC resource classes, ensure the following items are in effect:

NOTE 1:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Resource profiles are defined with a UACC(NONE).
2)	Access authorization restricts access to users requiring the ability to make process inquires.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

A set of sample commands are provided below to implement the minimum profiles necessary for proper security.  

/* THE FOLLOWING PROFILE FORCES GRANULAR PROFILES DEFINITIONS */
RDEF MQPROC ** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MQPROC DENY-BY-DEFAULT PROFILE')

RDEF MQPROC <ssid>.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('REQUIRED FOR ZWMQ0055')
PE <ssid>.** CL(MQPROC) ID(<ApplicableUsers>)

SETR RACL(MQPROC) REF

Note that an additional WebSphere MQ Refresh may be required for active Qmanagers.  This is done from the CONSOLE:

The example is for a Que Manager Named QMD1
>QMD1 REFRESH SECURITY(*)


The following is a sample of the commands required to allow a group (GRP1) to inquire on processes beginning with the letter V on queue manager (QM1):

RDEFINE MQPROC QM1.V* UACC(NONE) AUDIT(ALL(READ))
PERMIT QM1.V* CLASS(MQPROC) ID(GRP1) ACCESS(READ)"
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26245r521045_chk'
  tag severity: 'medium'
  tag gid: 'V-224562'
  tag rid: 'SV-224562r521047_rule'
  tag stig_id: 'ZWMQ0055'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26233r521046_fix'
  tag 'documentable'
  tag legacy: ['SV-7546', 'V-6966']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
