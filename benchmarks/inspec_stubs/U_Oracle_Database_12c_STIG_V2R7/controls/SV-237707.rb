control 'SV-237707' do
  title 'The DBMS must be protected from unauthorized access by developers on shared production/development host systems.'
  desc 'Applications employ the concept of least privilege for specific duties and information systems (including specific functions, ports, protocols, and services). The concept of least privilege is also applied to information system processes, ensuring that the processes operate at privilege levels no higher than necessary to accomplish required organizational missions and/or functions. Organizations consider the creation of additional processes, roles, and information system accounts as necessary to achieve least privilege. Organizations also apply least privilege concepts to the design, development, implementation, and operations of information systems.

Developers granted elevated database and/or operating system privileges on systems that support both development and production databases can affect the operation and/or security of the production database system. Operating system and database privileges assigned to developers on shared development and production systems must be restricted.'
  desc 'check', 'Identify whether any hosts contain both development and production databases. If no hosts contain both production and development databases, this is NA.

For any host containing both a development and a production database, determine if developers have been granted elevated privileges on the production database or on the OS.  If they have, ask for documentation that shows these accounts have formal approval and risk acceptance. If this documentation does not exist, this is a finding.

If developer accounts exist with the right to create and maintain tables (or other database objects) in production tablespaces, this is a finding.

(Where applicable, to check the number of instances on the host machine, check the /etc/oratab.  The /etc/oratab file is updated by the Oracle Installer when the database is installed when the root.sh file is executed.  Each line in the represents an ORACLE_SID:ORACLE_HOME:Y or N.  The ORACLE_SID and ORACLE_HOME are self-explanatory.  The Y or N signals the DBSTART program to automatically start or not start that specific instance when the machine is restarted.  Check with the system owner and application development team to see what each entry represents.  If a system is deemed to be a production system, review the system for development users.)'
  desc 'fix', "Restrict developer privileges to production objects to only objects and data where those privileges are required and authorized.  Document the approval and risk acceptance.

Consider using separate accounts for a person's developer duties and production duties.  At a minimum, use separate roles for developer privileges and production privileges.

If developers need the ability to create and maintain tables (or other database objects) as part of their development activities, provide dedicated tablespaces, and revoke any rights that allowed them to use production tablespaces for this purpose."
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40926r667151_chk'
  tag severity: 'medium'
  tag gid: 'V-237707'
  tag rid: 'SV-237707r879887_rule'
  tag stig_id: 'O121-C2-003800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-40889r667152_fix'
  tag 'documentable'
  tag legacy: ['V-61587', 'SV-76077']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
