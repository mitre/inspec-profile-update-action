control 'SV-254400' do
  title 'Windows Server 2022 directory service must be configured to terminate LDAP-based network connections to the directory server after five minutes of inactivity.'
  desc 'The failure to terminate inactive network connections increases the risk of a successful attack on the directory server. The longer an established session is in progress, the more time an attacker has to hijack the session, implement a means to passively intercept data, or compromise any protections on client access. For example, if an attacker gains control of a client computer, an existing (already authenticated) session with the directory server could allow access to the directory. The lack of confidentiality protection in LDAP-based sessions increases exposure to this vulnerability.

'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Open an elevated "Command Prompt" (run as administrator).

Enter "ntdsutil".

At the "ntdsutil:" prompt, enter "LDAP policies".

At the "ldap policy:" prompt, enter "connections".

At the "server connections:" prompt, enter "connect to server [host-name]"
(where [host-name] is the computer name of the domain controller).

At the "server connections:" prompt, enter "q".

At the "ldap policy:" prompt, enter "show values". 

If the value for MaxConnIdleTime is greater than "300" (5 minutes) or is not specified, this is a finding.

Enter "q" at the "ldap policy:" and "ntdsutil:" prompts to exit.

Alternately, Dsquery can be used to display MaxConnIdleTime:

Open "Command Prompt (Admin)".
Enter the following command (on a single line).

dsquery * "cn=Default Query Policy,cn=Query-Policies,cn=Directory Service, cn=Windows NT,cn=Services,cn=Configuration,dc=[forest-name]" -attr LDAPAdminLimits 

The quotes are required and dc=[forest-name] is the fully qualified LDAP name of the domain being reviewed (e.g., dc=disaost,dc=mil).

If the results do not specify a "MaxConnIdleTime" or it has a value greater than "300" (5 minutes), this is a finding.'
  desc 'fix', 'Configure the directory service to terminate LDAP-based network connections to the directory server after 5 minutes of inactivity.

Open an elevated "Command prompt" (run as administrator).

Enter "ntdsutil".

At the "ntdsutil:" prompt, enter "LDAP policies".

At the "ldap policy:" prompt, enter "connections".

At the "server connections:" prompt, enter "connect to server [host-name]" (where [host-name] is the computer name of the domain controller).

At the "server connections:" prompt, enter "q".

At the "ldap policy:" prompt, enter "Set MaxConnIdleTime to 300".

Enter "Commit Changes" to save.

Enter "Show values" to verify changes.

Enter "q" at the "ldap policy:" and "ntdsutil:" prompts to exit.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57885r849014_chk'
  tag severity: 'low'
  tag gid: 'V-254400'
  tag rid: 'SV-254400r849016_rule'
  tag stig_id: 'WN22-DC-000160'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-57836r849015_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
