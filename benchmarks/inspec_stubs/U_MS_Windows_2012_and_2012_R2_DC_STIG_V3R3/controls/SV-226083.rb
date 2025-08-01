control 'SV-226083' do
  title 'The directory service must be configured to terminate LDAP-based network connections to the directory server after five (5) minutes of inactivity.'
  desc 'The failure to terminate inactive network connections increases the risk of a successful attack on the directory server.  The longer an established session is in progress, the more time an attacker has to hijack the session, implement a means to passively intercept data, or compromise any protections on client access.  For example, if an attacker gains control of a client computer, an existing (already authenticated) session with the directory server could allow access to the directory.  The lack of confidentiality protection in LDAP-based sessions increases exposure to this vulnerability.'
  desc 'check', 'Verify the value for MaxConnIdleTime.

Open an elevated command prompt.
Enter "ntdsutil".
At the "ntdsutil:" prompt, enter "LDAP policies".
At the "ldap policy:" prompt, enter "connections".
At the "server connections:" prompt, enter "connect to server [host-name]".
(Where [host-name] is the computer name of the domain controller.)
At the "server connections:" prompt, enter "q".
At the "ldap policy:" prompt, enter "show values". 

If the value for MaxConnIdleTime is greater than 300 (the value for five minutes) or it is not specified, this is a finding.

Enter "q" at the "ldap policy:" and "ntdsutil:" prompts to exit.

Alternately, Dsquery can be used to display MaxConnIdleTime:

Open an elevated command prompt.
Enter the following command (on a single line).
dsquery * "cn=Default Query Policy,cn=Query-Policies,cn=Directory Service, cn=Windows NT,cn=Services,cn=Configuration,dc=[forest-name]" -attr LDAPAdminLimits 
The quotes are required and dc=[forest-name] is the fully qualified LDAP name of the domain being reviewed (e.g., dc=disaost,dc=mil).'
  desc 'fix', 'Configure the directory service to terminate LDAP-based network connections to the directory server after five (5) minutes of inactivity.

Open an elevated command prompt.
Enter "ntdsutil".
At the "ntdsutil:" prompt, enter "LDAP policies".
At the "ldap policy:" prompt, enter "connections".
At the "server connections:" prompt, enter "connect to server [host-name]".
(Where [host-name] is the computer name of the domain controller.)
At the "server connections:" prompt, enter "q".
At the "ldap policy:" prompt, enter "Set MaxConnIdleTime to 300".
Enter "Commit Changes" to save.
Enter "Show values" to verify changes.
Enter "q" at the "ldap policy:" and "ntdsutil:" prompts to exit.'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27785r794803_chk'
  tag severity: 'low'
  tag gid: 'V-226083'
  tag rid: 'SV-226083r794805_rule'
  tag stig_id: 'WN12-AD-000014-DC'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-27773r794804_fix'
  tag 'documentable'
  tag legacy: ['V-14831', 'SV-51188']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
