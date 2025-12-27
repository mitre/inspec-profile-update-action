control 'SV-224565' do
  title 'WebSphere MQ context resources defined to the MQADMIN resource class are not protected in accordance with security requirements.'
  desc 'Context security validates whether a userid has authority to pass or set identity and/or origin data
for a message. Context security will be active to avoid security exposure.  

This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following reports produced by the RACF Data Collection:

-	SENSITVE.RPT(MQADMIN)

b)	For all context resources (i.e., ssid.CONTEXT) defined to the MQADMIN resource class, ensure the following items are in effect:

NOTE 1:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Resource profiles are defined with a UACC(NONE).
2)	Access authorization restricts access to users requiring the ability to pass or set identity and/or origin data for a message.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

c)	If both of the items in (b) are true, there is NO FINDING.

d)	If either item in (b) is untrue, this is a FINDING.'
  desc 'fix', "Context security validates whether a userid has authority to pass or set identity and/or origin data for a message. Context security will be active, and all profiles ssid.CONTEXT will be defined to the MQADMIN class with UACC(NONE) specified, where ssid is the queue manager name.

Read access is required when the PASS option is specified for an MQOPEN or MQPUT1.  Update or control access is required when the SET or OUTPUT option is specified.

For all context resources (i.e., ssid.CONTEXT) defined to the MQADMIN resource class, ensure the following items are in effect:

NOTE 1:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Resource profiles are defined with a UACC(NONE).
2)	Access authorization restricts access to users requiring the ability to pass or set identity and/or origin data for a message.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

A set of sample commands are provided below to implement the minimum profiles necessary for proper security.  

/* THE FOLLOWING PROFILE FORCES GRANULAR PROFILES DEFINITIONS */
RDEF MQADMIN ** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MQADMIN DENY-BY-DEFAULT PROFILE')

RDEF MQADMIN <ssid>.CONTEXT UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MQADMIN PROFILE REQUIRED FOR CONTEXT SECURITY')

The following is a sample of the commands required to allow a systems programming group (SYS1) to offload and reload messages for queue manager (QMD1):

PERMIT QMD1.CONTEXT CLASS(MQADMIN) ID(SYS1) ACCESS(CONTROL)

The following refresh is required for RACListed classes:

SETR RACL(MQADMIN) REF

Note that an additional WebSphere MQ Refresh may be required for active Qmanagers.  This is done from the CONSOLE:

The example is for a Que Manager Named QMD1
>QMD1 REFRESH SECURITY(*)"
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26248r521054_chk'
  tag severity: 'medium'
  tag gid: 'V-224565'
  tag rid: 'SV-224565r521056_rule'
  tag stig_id: 'ZWMQ0058'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26236r521055_fix'
  tag 'documentable'
  tag legacy: ['SV-7552', 'V-6971']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
