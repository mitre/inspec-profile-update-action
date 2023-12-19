control 'SV-206549' do
  title 'Default demonstration and sample databases, database objects, and applications must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality, not required for every mission, that cannot be disabled.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to the DBMS and host system.'
  desc 'check', 'Review vendor documentation and vendor websites to identify vendor-provided demonstration or sample databases, database applications, objects, and files. 

Review the DBMS to determine if any of the demonstration and sample databases, database applications, or files are installed in the database or are included with the DBMS application.

If any are present in the database or are included with the DBMS application, this is a finding.'
  desc 'fix', 'Remove any demonstration and sample databases, database applications, objects, and files from the DBMS.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6809r291315_chk'
  tag severity: 'medium'
  tag gid: 'V-206549'
  tag rid: 'SV-206549r617447_rule'
  tag stig_id: 'SRG-APP-000141-DB-000090'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6809r291316_fix'
  tag 'documentable'
  tag legacy: ['SV-42760', 'V-32423']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
