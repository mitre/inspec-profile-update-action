control 'SV-82359' do
  title 'When using command-line tools such as SQLCMD in a mixed-mode authentication environment, users must use a logon method that does not expose the password.'
  desc 'To prevent the compromise of authentication information, such as passwords and PINs, during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk.

For example, displaying asterisks when a user types in a password or PIN, is an example of obscuring feedback of authentication information.

This requirement is applicable when mixed-mode authentication is enabled.  When this is the case, password-authenticated accounts can be created in and authenticated by SQL Server.  Other STIG requirements prohibit the use of mixed-mode authentication except when justified and approved.  This deals with the exceptions.

SQLCMD and other command-line tools are part of any SQL Server installation. These tools can accept a plain-text password, but do offer alternative techniques. Since the typical user of these tools is a database administrator, the consequences of password compromise are particularly serious. Therefore, the use of plain-text passwords must be prohibited, as a matter of practice and procedure.'
  desc 'check', %q(Run this query to determine whether SQL Server authentication is enabled:
EXEC master.sys.xp_loginconfig 'login mode'; 

If the config_value returned is "Windows NT Authentication", this is not a finding.

For SQLCMD, which cannot be configured not to accept a plain-text password, and any other essential tool with the same limitation, verify that the system documentation explains the need for the tool, who uses it, and any relevant mitigations; and that AO approval has been obtained; if not, this is a finding.

Request evidence that all users of the tool are trained in the importance of not using the plain-text password option and in how to keep the password hidden; and that they adhere to this practice; if not, this is a finding.)
  desc 'fix', "Where possible, change the login mode to Windows-only:
USE [master]
GO
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'LoginMode', REG_DWORD, 1;
GO

If mixed-mode authentication is necessary, then for SQLCMD, which cannot be configured not to accept a plain-text password when mixed-mode authentication is enabled, and any other essential tool with the same limitation:
1) Document the need for it, who uses it, and any relevant mitigations, and obtain AO approval.
2) Train all users of the tool in the importance of not using the plain-text password option and in how to keep the password hidden."
  impact 0.7
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68437r1_chk'
  tag severity: 'high'
  tag gid: 'V-67869'
  tag rid: 'SV-82359r1_rule'
  tag stig_id: 'SQL4-00-039020'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-73985r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
