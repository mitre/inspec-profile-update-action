control 'SV-225654' do
  title 'The Samsung SDS EMM must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'The organization-defined number of concurrent sessions should be defined in the site security plan.  Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by using information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application. 

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.

SFR ID: FMT_SMF.1.1(2) b / AC-10

'
  desc 'check', 'Review the Samsung SDS EMM configuration settings and verify the server is configured to limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Setting >> Server >> Configuration and verify Multiple login is set to "Disallow".

If the MDM console Multiple login is not set to "Disallow", this is a finding.'
  desc 'fix', 'Configure the Samsung SDS EMM to limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Setting >> Server >> Configuration and check Multiple login as "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27355r560984_chk'
  tag severity: 'medium'
  tag gid: 'V-225654'
  tag rid: 'SV-225654r588007_rule'
  tag stig_id: 'SSDS-00-200070'
  tag gtitle: 'PP-MDM-431010'
  tag fix_id: 'F-27343r560985_fix'
  tag satisfies: ['SRG-APP-000001', 'PP-MDM-431010']
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
