control 'SV-223864' do
  title 'The IBM z/OS startup user account for the z/OS UNIX Telnet Server must be properly defined.'
  desc 'The PROFILE.TCPIP configuration file provides system operation and configuration parameters for the TN3270 Telnet Server. Several of these parameters have potential impact to system security. Failure to code the appropriate values could result in unexpected operations and degraded security. This exposure may result in unauthorized access impacting data integrity or the availability of some system services.'
  desc 'check', 'From the ISPF Command Shell enter:
omvs
cd /etc
cat inetd.conf

If the otelnetd command specifies any user other than OMVS or OMVSKERN, this is a finding.'
  desc 'fix', 'The user account used at the startup of otelnetd is specified in the inetd configuration file. This account is used to perform the identification and authentication of the user requesting the session. Because the account is only used until user authentication is completed, there is no need for a unique account for this function. The z/OS UNIX kernel account can be used.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25537r515280_chk'
  tag severity: 'medium'
  tag gid: 'V-223864'
  tag rid: 'SV-223864r604139_rule'
  tag stig_id: 'RACF-UT-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25525r515281_fix'
  tag 'documentable'
  tag legacy: ['V-98435', 'SV-107539']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
