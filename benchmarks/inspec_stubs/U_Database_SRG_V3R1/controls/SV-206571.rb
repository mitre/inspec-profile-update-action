control 'SV-206571' do
  title 'The DBMS must isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. 

Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.'
  desc 'check', 'Check DBMS settings to determine whether objects or code implementing security functionality are located in a separate security domain, such as a separate database or schema created specifically for security functionality.

If security-related database objects or code are not kept separate, this is a finding.'
  desc 'fix', 'Locate security-related database objects and code in a separate database, schema, or other separate security domain from database objects and code implementing application logic.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6831r291381_chk'
  tag severity: 'medium'
  tag gid: 'V-206571'
  tag rid: 'SV-206571r617447_rule'
  tag stig_id: 'SRG-APP-000233-DB-000124'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-6831r291382_fix'
  tag 'documentable'
  tag legacy: ['SV-42873', 'V-32536']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
