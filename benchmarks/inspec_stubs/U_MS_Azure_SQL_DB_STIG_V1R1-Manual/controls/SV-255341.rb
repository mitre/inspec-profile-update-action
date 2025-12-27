control 'SV-255341' do
  title 'Azure SQL Database must prevent nonprivileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 

System documentation must include a definition of the functionality considered privileged. 

Depending on circumstances, privileged functions can include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from Nonprivileged users. 

A privileged function in Azure SQL Database context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. 

In an Azure SQL Database environment, it encompasses, but is not necessarily limited to: 

CREATE 
ALTER 
DROP 
GRANT 
REVOKE 
DENY 

There may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. 

Possible examples include: 

TRUNCATE TABLE; 
DELETE, or 
DELETE affecting more than n rows, for some n, or 
DELETE without a WHERE clause; 

UPDATE or 
UPDATE affecting more than n rows, for some n, or 
UPDATE without a WHERE clause; 

Any SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal. 

Depending on the capabilities of Azure SQL Database and the design of the database and associated applications, the prevention of unauthorized use of privileged functions may be achieved by means of Azure SQL Database security features, database triggers, other mechanisms, or a combination of these.'
  desc 'check', 'Review Azure SQL Database securables and built-in role membership to ensure only authorized users have privileged access and the ability to create server-level objects and grant permissions to themselves or others. 

Review the system documentation to determine the required levels of protection for Azure SQL Database securables.

Review the permissions in place in the control and data planes in Azure SQL Database. If the actual permissions do not match the documented requirements, this is a finding. 

Ensure only the documented and approved logins have privileged functions in Azure SQL Database. 

If the current configuration does not match the documented baseline, this is a finding.'
  desc 'fix', 'Restrict permissions to Azure SQL Database securables to only authorized users.'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59014r871147_chk'
  tag severity: 'medium'
  tag gid: 'V-255341'
  tag rid: 'SV-255341r871149_rule'
  tag stig_id: 'ASQL-00-010400'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag fix_id: 'F-58958r871148_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
