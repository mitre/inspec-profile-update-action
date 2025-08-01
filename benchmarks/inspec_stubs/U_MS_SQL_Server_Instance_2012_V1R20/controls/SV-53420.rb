control 'SV-53420' do
  title 'A single SQL Server database connection configuration file (or a single set of credentials) must not be used to configure all database clients.'
  desc 'Applications employ the concept of least privilege for specific duties and information systems (including specific functions, ports, protocols, and services). The concept of least privilege is also applied to information system processes, ensuring that the processes operate at privilege levels no higher than necessary to accomplish required organizational missions and/or functions. Organizations consider the creation of additional processes, roles, and information system accounts as necessary to achieve least privilege. Organizations also apply least privilege concepts to the design, development, implementation, and operations of information systems.

Many sites distribute a single SQL Server connection configuration file to all site database users that contains network access information for all databases on the site. Such a file provides information to access SQL Server databases not required by all users that may assist in unauthorized access attempts.'
  desc 'check', 'Check procedures for providing SQL Server database connection information to users/applications. If procedures do not indicate or implement restrictions to connections required by the particular user/application which indicate process of least privilege and specific authorization was employed, this is a finding.'
  desc 'fix', 'Implement procedures to supply SQL Server database connection information to only those databases authorized for the user.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47662r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41045'
  tag rid: 'SV-53420r2_rule'
  tag stig_id: 'SQL2-00-009100'
  tag gtitle: 'SRG-APP-000062-DB-000012'
  tag fix_id: 'F-46344r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002220']
  tag nist: ['CM-6 b', 'AC-5 b']
end
