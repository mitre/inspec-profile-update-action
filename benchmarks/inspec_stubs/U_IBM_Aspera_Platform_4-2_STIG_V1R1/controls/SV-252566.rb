control 'SV-252566' do
  title 'IBM Aspera Console must prevent concurrent logins for all accounts.'
  desc 'Limiting the number of current sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be the same as the requirements specified for the application for which it serves as intermediary.

This policy only applies to application gateways/firewalls (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'Verify IBM Aspera Console prevents concurrent logins for all accounts: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Security" section.
- Verify the "Prevent concurrent login" option is checked.

If the "Prevent concurrent login" option is not checked, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Console to prevent concurrent logins for all accounts: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Security" section.
- Put a check the "Prevent concurrent login" check box.
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56022r817866_chk'
  tag severity: 'medium'
  tag gid: 'V-252566'
  tag rid: 'SV-252566r817868_rule'
  tag stig_id: 'ASP4-CS-040190'
  tag gtitle: 'SRG-NET-000053-ALG-000001'
  tag fix_id: 'F-55972r817867_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
