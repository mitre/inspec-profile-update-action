control 'SV-87253' do
  title 'The Cassandra database must have the correct authorizer value.'
  desc 'Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access the DBMS.  To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies. 

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications, a category that includes database management systems.  If the DBMS does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', "Check the Cassandra Server settings to determine whether users are restricted from accessing objects and data they are not authorized to access.

At the command prompt, execute the following command:

# grep '^\\s*authorizer:' /usr/lib/vmware-vcops/user/conf/cassandra/cassandra.yaml

If the line below is returned, this is a finding:
authorizer: AllowAllAuthorizer"
  desc 'fix', "Configure the Cassandra Server settings and access controls to permit user access only to objects and data that the user is authorized to view or interact with, and to prevent access to all other objects and data.

At the command line execute the following command:

# sed -i 's/^.*\\bauthorizer:.*$/authorizer: CassandraAuthorizer/' /usr/lib/vmware-vcops/user/conf/cassandra/cassandra.yaml"
  impact 0.7
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72775r1_chk'
  tag severity: 'high'
  tag gid: 'V-72621'
  tag rid: 'SV-87253r1_rule'
  tag stig_id: 'VROM-CS-000005'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-79023r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
