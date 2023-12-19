control 'SV-225649' do
  title 'The Samsung SDS EMM server must be configured to use one-time password in addition to username and password for administrator logon to the server.'
  desc 'Two-factor authentication ensures strong authentication and access controls are in place for privileged accounts.

SFR ID: FIA'
  desc 'check', 'Verify the EMM server has been configured to use one-time password (OTP) for administrator logon to the server.

On the MDM console, do the following:
1. In the Admin Console login page, enter the Admin ID and password and click the "Sign in" button.
2. Enter the OTP in the pop-up by sending SMS or email that is registered in admin account information.
3. Login is successful.

If the EMM server has not been configured to use OTP for administrator logon to the server, this is a finding.'
  desc 'fix', 'Use the following procedure for configuring the use of OTP authentication on the EMM server:

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Setting >> Server >> Configuration and set Two-Factor Authentication to "Yes".
3. Click "Save".'
  impact 0.7
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27350r547732_chk'
  tag severity: 'high'
  tag gid: 'V-225649'
  tag rid: 'SV-225649r547734_rule'
  tag stig_id: 'SSDS-00-000725'
  tag gtitle: 'PP-MDM-414003'
  tag fix_id: 'F-27338r547733_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
