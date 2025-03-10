control 'SV-238440' do
  title 'A single database connection configuration file must not be used to configure all database clients.'
  desc 'Applications employ the concept of least privilege for specific duties and information systems (including specific functions, ports, protocols, and services). The concept of least privilege is also applied to information system processes, ensuring that the processes operate at privilege levels no higher than necessary to accomplish required organizational missions and/or functions. Organizations consider the creation of additional processes, roles, and information system accounts as necessary to achieve least privilege. Organizations also apply least privilege concepts to the design, development, implementation, and operations of information systems.

Many sites distribute a single client database connection configuration file to all site database users that contains network access information for all databases on the site. Such a file provides information to access databases not required by all users that may assist in unauthorized access attempts.'
  desc 'check', 'Review procedures for providing database connection information to users/user workstations. If procedures do not indicate or implement restrictions to connections required by the particular user, this is a finding.

Note: This check is specific for the DBMS host system and not directed at client systems (client systems are included in the Application STIG/Checklist); however, detection of unauthorized client connections to the DBMS host system obtained through log files should be performed regularly and documented where authorized.'
  desc 'fix', 'Implement procedures to supply database connection information to only those databases authorized for the user.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41651r667492_chk'
  tag severity: 'medium'
  tag gid: 'V-238440'
  tag rid: 'SV-238440r667494_rule'
  tag stig_id: 'O112-C2-003600'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-41610r667493_fix'
  tag 'documentable'
  tag legacy: ['V-52373', 'SV-66589']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
