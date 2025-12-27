control 'SV-251264' do
  title 'The Workspace ONE UEM must use multifactor authentication for local access to privileged accounts.'
  desc 'To ensure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication is defined as using two or more factors to achieve authentication. 

Factors include: 
(i) Something a user knows (e.g., password/PIN);
(ii) Something a user has (e.g., cryptographic identification device, token); or
(iii) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

Applications integrating with the DoD Active Directory and utilize the DoD Common Access Card (CAC) are examples of compliant multifactor authentication solutions.

SFR ID: FMT_SMF.1(2)b. / IA-2(3)'
  desc 'check', 'Verify WS1 UEM is using multifactor authentication for the local emergency account.

Use one of the following two methods to confirm compliance:

Method 1
Have the emergency account admin user log into the emergency account and verify the server requires 2FA before console access is granted.

Method 2
1. Log in to the WS1UEM console.
2. Go to Accounts >> Administrators >> List View.
3. Select the Emergency account user and double-click on the account.
4. In the Add/Edit Admin screen, verify  "Two-Factor Authentication" has been selected with either Email of SMS. Verify Notification has been selected and the token expiration time is 10 minutes or less.

If WS1 UEM is not using multifactor authentication for the local emergency account, this is a finding.'
  desc 'fix', 'Configure WS1 UEM to use multifactor authentication for the local emergency account.

1. Log in to the WS1UEM console.
2. Go to Accounts >> Administrators >> List View.
3. Select Add, then Add Admin.
4. Select "Basic" for the User Type and fill in user name, password, etc.
5. Select "Two-Factor Authentication and then select email or SMS as the delivery method and 10 minutes or less token expiration time.
6. Select either email or SMS Notification.
7. Complete all other required fields in the enrollment form, including either the telephone number or email address of the emergency account user.
8. Select Save.'
  impact 0.7
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-54699r805094_chk'
  tag severity: 'high'
  tag gid: 'V-251264'
  tag rid: 'SV-251264r805096_rule'
  tag stig_id: 'VMW1-00-200190'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-54653r805095_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
