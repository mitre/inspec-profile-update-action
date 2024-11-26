control 'SV-253702' do
  title 'MariaDB must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Normally, with PKI authentication, the interaction with the user for authentication will be handled by a software component separate from the DBMS, such as ActivIdentity ActivClient. However, in cases where the DBMS controls the interaction, this requirement applies.

To prevent the compromise of authentication information such as passwords and PINs during the authentication process, the feedback from the system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism. 

Obfuscation of user-provided authentication secrets when typed into the system is a method used in addressing this risk. 

Displaying asterisks when a user types in a password or a smart card PIN is an example of obscuring feedback of authentication secrets.

This calls for review of applications, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'Verify best practices are documented and users trained to use the password command line interface flags appropriately. 

For example, the command line option --password (or -p) prompts for a password to be entered and obscures feedback on the typed in password. 

Ensure users are trained to use alternatives to command line password parameters, if they are not, this is a finding.'
  desc 'fix', 'When connecting to the database, the username and password are sent to the server via the command line interface or other connector interface. Using the command line interface, passing the -p or --password flags but not including the password in the command will prompt for the password and not display it on the screen as typed. 

Example: 

mariadb -u username -p'
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57154r841629_chk'
  tag severity: 'high'
  tag gid: 'V-253702'
  tag rid: 'SV-253702r841631_rule'
  tag stig_id: 'MADB-10-004300'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-57105r841630_fix'
  tag 'documentable'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
