control 'SV-224564' do
  title 'WebSphere MQ Alternate User resources defined to MQADMIN resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following reports produced by the RACF Data Collection:

-	SENSITVE.RPT(MQADMIN)

b)	For all alternate user resources (i.e., ssid.ALTERNATE.USER.alternateuserid) defined to the MQADMIN resource class, ensure the following items are in effect:

NOTE 1:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Resource profiles are defined with a UACC(NONE).
2)	Access authorization restricts access to users requiring the ability to use the alternate userid.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

c)	If both of the items in (b) are true, there is NO FINDING.

d)	If either item in (b) is untrue, this is a FINDING.'
  desc 'fix', "Alternate userid security allows access to be requested under another userid. Alternate userid security will be active, and all profiles ssid.ALTERNATE.USER.alternateuserid will be defined to the MQADMIN class with UACC(NONE) specified. Restrict update access to those userids requiring access to alternate userids.

For all alternate user resources (i.e., ssid.ALTERNATE.USER.alternateuserid) defined to the MQADMIN resource class, ensure the following items are in effect:

NOTE 1:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Resource profiles are defined with a UACC(NONE).
2)	Access authorization restricts access to users requiring the ability to use the alternate userid.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

A set of sample commands are provided below to implement the minimum profiles necessary for proper security.  

/* THE FOLLOWING PROFILE FORCES GRANULAR PROFILES DEFINITIONS */
RDEF MQADMIN ** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MQADMIN DENY-BY-DEFAULT PROFILE')

RDEF MQADMIN <ssid>.ALTERNATE.USER.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MQADMIN DENY-BY-DEFAULT for ALT USER PROFILE')

The following is a sample of the commands required to allow payroll server (PAYSRV1) to specify alternate userids starting with the characters PS on queue manager (QM1):

RDEFINE MQADMIN QMD1.ALTERNATE.USER.PS* UACC(NONE) AUDIT(ALL)

PERMIT QMD1.ALTERNATE.USER.PS* CLASS(MQADMIN) ID(PAYSRV1) ACCESS(UPDATE)

SETR RACL(MQADMIN) REF

Note that an additional WebSphere MQ Refresh may be required for active Qmanagers.  This is done from the CONSOLE:

The example is for a Que Manager Named QMD1
>QMD1 REFRESH SECURITY(*)"
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26247r521051_chk'
  tag severity: 'medium'
  tag gid: 'V-224564'
  tag rid: 'SV-224564r521053_rule'
  tag stig_id: 'ZWMQ0057'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26235r521052_fix'
  tag 'documentable'
  tag legacy: ['SV-7550', 'V-6969']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
