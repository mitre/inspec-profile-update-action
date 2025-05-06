control 'SV-87299' do
  title 'The Cassandra Server must isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. 

Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.'
  desc 'check', 'Review the Cassandra Server configuration to ensure objects or code implementing security functionality are located in a separate security domain, such as a separate database or schema created specifically for security functionality.

If security-related database objects or code are not kept separate, this is a finding.

Open "cqlsh" prompt of Cassandra Server and run "LIST ALL PERMISSIONS" command from it. Review username resource and permissions columns.

If for any of the objects under system, system_auth, or system_traces schemas privileges are given to any other users than a superuser (cassandra in default configuration), this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to isolate security functions from non-security functions.

Locate security-related database objects and code in a separate database, schema, or other separate security domain from database objects and code implementing application logic.

Using the "REVOKE" command, modify access privileges for objects in system, system_auth, and system_traces, revoking privileges of non-superuser users.'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72823r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72667'
  tag rid: 'SV-87299r1_rule'
  tag stig_id: 'VROM-CS-000175'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-79071r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
