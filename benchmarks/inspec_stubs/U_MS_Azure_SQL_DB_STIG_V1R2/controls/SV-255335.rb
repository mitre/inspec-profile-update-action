control 'SV-255335' do
  title 'Azure SQL Database must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 

(ii) Accesses that occur through authorized use of group authenticators without individual authentication. 

Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity.'
  desc 'check', 'Review Azure SQL Database users to determine whether shared accounts exist. (This does not include the case where Azure SQL Database has a guest or public account that is providing access to publicly available information.) 

If accounts are determined to be shared, determine if individuals are first individually authenticated. Where an application connects to Azure SQL Database using a standard, shared account, ensure it also captures the individual user identification and passes it to Azure SQL Database. 

If individuals are not individually authenticated before using the shared account (e.g., by the operating system or possibly by an application making calls to the database), this is a finding. 

If accounts are determined to be shared, determine if they are directly accessible to end users. If so, this is a finding.'
  desc 'fix', 'Remove user-accessible shared accounts and use individual user IDs. 

If necessary, use the DROP USER command to remove user-accessible shared accounts. Example provided below.

DROP USER SharedAccount;

https://docs.microsoft.com/en-us/sql/t-sql/statements/drop-user-transact-sql'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59008r871129_chk'
  tag severity: 'medium'
  tag gid: 'V-255335'
  tag rid: 'SV-255335r879589_rule'
  tag stig_id: 'ASQL-00-007800'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-58952r871130_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
