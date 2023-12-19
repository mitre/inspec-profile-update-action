control 'SV-225649' do
  title 'The Samsung SDS EMM server must be configured to use one-time password in addition to username and password for administrator logon to the server.'
  desc 'Two-factor authentication ensures strong authentication and access controls are in place for privileged accounts. But One-Time Passwords (OTP) do not meet DoD requirements that system administrators access privileged accounts via CAC authentication through a directory service (Active Directory).

SFR ID: FIA'
  desc 'check', 'Verify the EMM server has not been configured to use one-time password (OTP) for administrator logon to the server. 
 
On the MDM console, do the following: 
1.  Log into the SDS EMM console.
2.  Go to Setting >> Server >> Configuration >> Two-Factor Authentication.
3.  Verify Two-Factor Authentication is set to "No".
 
If the EMM server has not been configured to disable one-time-password (OTP) for administrator logon to the server, this is a finding.'
  desc 'fix', 'Use the following procedure for configuring the use of OTP authentication on the EMM server: 
 
On the MDM console, do the following: 
1.  Log into the SDS EMM console.
2.  Go to Setting >> Server >> Configuration >> Two-Factor Authentication.
3.  Set Two-Factor Authentication to "No".
4.  Save setting.'
  impact 0.7
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27350r744402_chk'
  tag severity: 'high'
  tag gid: 'V-225649'
  tag rid: 'SV-225649r744410_rule'
  tag stig_id: 'SSDS-00-000725'
  tag gtitle: 'PP-MDM-414003'
  tag fix_id: 'F-27338r744403_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
