control 'SV-224357' do
  title 'User timeout parameter values for WebSphere MQ queue managers are not specified in accordance with security requirements.'
  desc 'Users signed on to a WebSphere MQ queue manager could leave their terminals unattended for long periods of time.  This may allow unauthorized individuals to gain access to WebSphere MQ resources and application data.  This exposure could compromise the availability, integrity, and confidentiality of some system services and application data.'
  desc 'check', 'a)	Refer to the following report produced by the z/OS Data Collection:

-	MQSRPT(ssid)

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZWMQ0020)

b)	Review the ssid report(s) and perform the following steps:

1)	Find the DISPLAY SECURITY command to locate the start of the security parameter settings.
2)	Review the CSQH015I and CSQH016I messages to determine the Timeout and Interval parameter settings respectively.
3)	Repeat these steps for each queue manager ssid.

The standard values are:

TIMEOUT(15)
INTERVAL(5)

c)	If the Timeout and Interval values conform to the standard values, there is NO FINDING.

d)	If the Timeout and/or Interval values do not conform to the standard values, this is a FINDING.'
  desc 'fix', 'Review the WebSphere MQ System Setup Guide and the information on the ALTER SECURITY command in the  WebSphere MQ Script (MQSC) Command Reference.

Ensure the values for the TIMEOUT and INTERVAL parameters are specified in accordance with security requirements.'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26034r520970_chk'
  tag severity: 'medium'
  tag gid: 'V-224357'
  tag rid: 'SV-224357r520972_rule'
  tag stig_id: 'ZWMQ0020'
  tag gtitle: 'SRG-OS-000163'
  tag fix_id: 'F-26022r520971_fix'
  tag 'documentable'
  tag legacy: ['V-3903', 'SV-3903']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
