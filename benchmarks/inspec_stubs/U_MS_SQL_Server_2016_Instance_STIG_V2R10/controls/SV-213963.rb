control 'SV-213963' do
  title 'SQL Server must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.  
 
Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following: 
 
(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and  
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity.'
  desc 'check', 'Review SQL Server users to determine whether shared accounts exist. (This does not include the case where SQL Server has a guest or public account that is providing access to publicly available information.)    
 
If accounts are determined to be shared, determine if individuals are first individually authenticated. Where an application connects to SQL Server using a standard, shared account, ensure that it also captures the individual user identification and passes it to SQL Server. 
 
If individuals are not individually authenticated before using the shared account (e.g., by the operating system or possibly by an application making calls to the database), this is a finding.  
 
If accounts are determined to be shared, determine if they are directly accessible to end users. If so, this is a finding.'
  desc 'fix', "Remove user-accessible shared accounts and use individual userIDs.  
 
Configure applications to ensure successful individual authentication prior to shared account access.  
 
Ensure each user's identity is received and used in audit data in all relevant circumstances."
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15180r313672_chk'
  tag severity: 'medium'
  tag gid: 'V-213963'
  tag rid: 'SV-213963r879589_rule'
  tag stig_id: 'SQL6-D0-007800'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-15178r313673_fix'
  tag 'documentable'
  tag legacy: ['SV-93895', 'V-79189']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
