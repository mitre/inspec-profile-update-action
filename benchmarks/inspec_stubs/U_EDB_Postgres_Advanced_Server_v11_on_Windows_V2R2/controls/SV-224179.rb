control 'SV-224179' do
  title 'The EDB Postgres Advanced Server must isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles.

Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.'
  desc 'check', 'All PPAS built-in security packages are in the sys, pg_catalog, information_schema, and dbo schemas.

If any application-specific packages have been added to these schemas, this is a finding.'
  desc 'fix', 'Remove all application-specific packages that were added to the sys, pg_catalog, information_schema, and dbo schemas.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25852r495555_chk'
  tag severity: 'medium'
  tag gid: 'V-224179'
  tag rid: 'SV-224179r508023_rule'
  tag stig_id: 'EP11-00-005800'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-25840r495556_fix'
  tag 'documentable'
  tag legacy: ['SV-109485', 'V-100381']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
