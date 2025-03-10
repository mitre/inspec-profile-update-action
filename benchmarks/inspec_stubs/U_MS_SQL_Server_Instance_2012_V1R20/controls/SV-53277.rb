control 'SV-53277' do
  title 'SQL Server must ensure users are authenticated with an individual authenticator prior to using a shared authenticator.'
  desc %q(To ensure individual accountability and prevent unauthorized access, application users (and any processes acting on behalf of users) must be individually identified and authenticated.

A shared authenticator is a generic account used by multiple individuals. Use of a shared authenticator alone does not uniquely identify individual users. An example of a shared authenticator is the UNIX OS 'root' user account, a Windows 'administrator' account, an 'sa' account, or a 'helpdesk' account.

Legitimate use of shared accounts includes, for example, connection pooling.  Since this is insufficient to ensure non-repudiation, such shared accounts should be kept "under the covers," be inaccessible directly to end users, be invoked only after successful individual authentication, be communicated to the DBMS by the application, and be recorded in all relevant audit contexts.

(Shared accounts should not be confused with Windows groups, which are used in role-based access control.))
  desc 'check', 'Review SQL Server users to determine whether shared accounts exist.

If accounts are determined to be shared, determine if individuals are first individually authenticated. If individuals are not individually authenticated before using the shared account (e.g., by the operating system or possibly by an application making calls to the database), this is a finding.

If accounts are determined to be shared, determine if they are directly accessible to end users.  If so, this is a finding.'
  desc 'fix', "Remove user-accessible shared accounts and use individual userids.

Build/configure applications to ensure successful individual authentication prior to shared account access.

Ensure each user's identity is received and used in audit data in all relevant circumstances."
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47578r4_chk'
  tag severity: 'medium'
  tag gid: 'V-40923'
  tag rid: 'SV-53277r3_rule'
  tag stig_id: 'SQL2-00-018500'
  tag gtitle: 'SRG-APP-000153-DB-000108'
  tag fix_id: 'F-46205r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
