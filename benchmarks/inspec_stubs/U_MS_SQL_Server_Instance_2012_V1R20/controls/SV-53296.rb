control 'SV-53296' do
  title 'SQL Server must have the publicly available AdventureWorks sample database removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plug-ins not related to requirements and providing a wide array of functionality not required for every mission, but which cannot be disabled.

Applications must adhere to the principles of least functionality by providing only essential capabilities. Even though the very popular "AdventureWorks" database is no longer available by default, it introduces a vulnerability to SQL Server and must be removed.

Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to the SQL Server and the OS.'
  desc 'check', %q(Check SQL Server for the existence of the publicly available "AdventureWorks" database by performing the following query:

SELECT name from sysdatabases where name like 'AdventureWorks%';

If the "AdventureWorks" database is present, this is a finding.)
  desc 'fix', 'Remove the publicly available "AdventureWorks" database from SQL Server by running the following query:

DROP DATABASE AdventureWorks'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47597r3_chk'
  tag severity: 'medium'
  tag gid: 'V-40942'
  tag rid: 'SV-53296r3_rule'
  tag stig_id: 'SQL2-00-016300'
  tag gtitle: 'SRG-APP-000141-DB-000090'
  tag fix_id: 'F-46224r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
