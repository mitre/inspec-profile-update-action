control 'SV-225657' do
  title 'The Samsung SDS EMM must use multifactor authentication for local access to privileged accounts.'
  desc 'To ensure accountability and prevent unauthenticated access, privileged users must use multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication is defined as using two or more factors to achieve authentication. 

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). 

A privileged account is defined as an information system account with authorizations of a privileged user. 

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network. 

Applications integrating with the DoD Active Directory and using the DoD CAC are examples of compliant multifactor authentication solutions.

SFR ID: FMT_SMF.1(2)b. / IA-2(3)

'
  desc 'check', 'Review the Samsung SDS EMM configuration settings and verify the server is configured to use multifactor authentication for local access to privileged accounts.

On the MDM console, do the following:
1. In the Admin Console login page, enter the Admin ID and password and click the "Sign in" button.
2. Enter the OTP (one-time password) in the pop-up by sending SMS or email that is registered in admin account information.
3. Login is successful.

If the OTP pop-up does not display, this is a finding.'
  desc 'fix', 'Configure the Samsung SDS EMM to use multifactor authentication for local access to privileged accounts.

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Setting >> Server >> Configuration and set Two-Factor Authentication to "Yes".
3. Click "Save".'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27358r547756_chk'
  tag severity: 'medium'
  tag gid: 'V-225657'
  tag rid: 'SV-225657r547758_rule'
  tag stig_id: 'SSDS-00-200260'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-27346r547757_fix'
  tag satisfies: ['SRG-APP-000151', 'PP-MDM-991000']
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
