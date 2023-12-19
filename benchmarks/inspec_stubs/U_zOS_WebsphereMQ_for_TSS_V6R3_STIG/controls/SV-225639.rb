control 'SV-225639' do
  title 'WebSphere MQ RESLEVEL resources in the MQADMIN resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(WHOHMADM)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZWMQ0060)

b)	Access authorization to these RESLEVEL resources restricts all access.  No users are permitted access to ssid.RESLEVEL resources in the MQADMIN resource class.

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

c)	If (b) is true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', 'RESLEVEL security profiles control the number of userids checked for API resource security.  RESLEVEL security will not be implemented due to the following exposures and limitations:

(1)	RESLEVEL is a powerful option that can cause the bypassing of all security checks.

(2)	Security audit records are not created when the RESLEVEL profile is utilized.

(3)	If the WARNING option is specified on a RESLEVEL profile, no warning messages are produced.

In order to protect against any profile in the MQADMIN class, such as ssid.**, resolving to a RESLEVEL profile, an ssid.RESLEVEL permission will be created for each queue manager with an access of none.

The following sample command prevents access to ssid.RESLEVEL:

 TSS PER(ALL) MQADMIN(ssid.RESLEVEL) ACCESS(NONE)'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27340r472719_chk'
  tag severity: 'medium'
  tag gid: 'V-225639'
  tag rid: 'SV-225639r472721_rule'
  tag stig_id: 'ZWMQ0060'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27328r472720_fix'
  tag 'documentable'
  tag legacy: ['V-6975', 'SV-7557']
  tag cci: ['CCI-000213', 'CCI-001762']
  tag nist: ['AC-3', 'CM-7 (1) (b)']
end
