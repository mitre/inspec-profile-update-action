control 'SV-82353' do
  title 'SQL Server must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To ensure accountability and prevent unauthorized SQL Server access, organizational users shall be identified and authenticated.

Organizational users include organizational employees and individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations).

Users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which must outline specific user actions that can be performed on SQL Server without identification or authentication.'
  desc 'check', 'Review SQL Server users to determine whether shared accounts exist. (This does not include the case where SQL Server has a guest or public account that is providing access to publicly available information.)

If accounts are determined to be shared, determine if individuals are first individually authenticated.

If individuals are not individually authenticated before using the shared account (e.g., by the operating system or possibly by an application making calls to the database), this is a finding.

If accounts are determined to be shared, determine if they are directly accessible to end users.  If so, this is a finding.'
  desc 'fix', "Remove user-accessible shared accounts and use individual userids.

Build/configure applications to ensure successful individual authentication prior to shared account access.

Ensure each user's identity is received and used in audit data in all relevant circumstances."
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68431r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67863'
  tag rid: 'SV-82353r1_rule'
  tag stig_id: 'SQL4-00-018400'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-73979r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
