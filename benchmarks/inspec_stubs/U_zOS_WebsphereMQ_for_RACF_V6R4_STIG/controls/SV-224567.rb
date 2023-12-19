control 'SV-224567' do
  title 'WebSphere MQ RESLEVEL resources in the MQADMIN resource class are not protected in accordance with security requirements.'
  desc 'RESLEVEL security profiles control the number of userids checked for API-resource security.
RESLEVEL is a powerful option that can cause the bypassing of all security checks.
RESLEVEL security will not be implemented.'
  desc 'check', 'a)	Refer to the following reports produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(MQADMIN)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZWMQ0060)

b)	Ensure the following items are in effect:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	A RESLEVEL resource (i.e., ssid.RESLEVEL) is defined for each queue manager to the MQADMIN resource class with a UACC(NONE).
2)	Access authorization to these RESLEVEL resources restricts all access.  No users or groups must be specified in the access list.

c)	If both of the items in (b) are true, there is NO FINDING.

d)	If either item in (b) is untrue, this is a FINDING.'
  desc 'fix', "RESLEVEL security profiles control the number of userids checked for API-resource security.  RESLEVEL security will not be implemented due to the following exposures and limitations:
(1) RESLEVEL is a powerful option that can cause the bypassing of all security checks.
(2) Security audit records are not created when the RESLEVEL profile is utilized.
(3) If the WARNING option is specified on a RESLEVEL profile, no warning messages are produced.

To protect against any profile in the MQADMIN class, such as ssid.**, resolving to a RESLEVEL profile, a ssid.RESLEVEL profile will be defined for each queue manager with
UACC(NONE) specified and no users or groups specified in the access list.

Ensure the following items are in effect:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	A RESLEVEL resource (i.e., ssid.RESLEVEL) is defined for each queue manager to the MQADMIN resource class with a UACC(NONE).
2)	Access authorization to these RESLEVEL resources restricts all access.  No users or groups must be specified in the access list.

A set of sample commands are provided below to implement the profile necessary for proper security.  

RDEF MQADMIN <ssid>.RESLEVEL UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('MQADMIN PROFILE REQUIRED BY ZWMQ0060')

SETR RACL(MQADMIN) REF

Note that an additional WebSphere MQ Refresh may be required for active Qmanagers.  This is done from the CONSOLE:

The example is for a Que Manager Named QMD1
>QMD1 REFRESH SECURITY(*)"
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26250r521060_chk'
  tag severity: 'medium'
  tag gid: 'V-224567'
  tag rid: 'SV-224567r855248_rule'
  tag stig_id: 'ZWMQ0060'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26238r521061_fix'
  tag 'documentable'
  tag legacy: ['SV-7556', 'V-6975']
  tag cci: ['CCI-001762', 'CCI-000213']
  tag nist: ['CM-7 (1) (b)', 'AC-3']
end
