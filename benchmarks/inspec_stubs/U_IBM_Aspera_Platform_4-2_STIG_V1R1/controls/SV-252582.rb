control 'SV-252582' do
  title 'IBM Aspera Faspex must prevent concurrent logins for all accounts.'
  desc 'Limiting the number of current sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be the same as the requirements specified for the application for which it serves as intermediary.

This policy only applies to application gateways/firewalls (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Faspex prevents concurrent logins for all accounts: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Verify the "Faspex accounts" "Prevent concurrent login" option is checked.

If the "Prevent concurrent login" is not checked, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Faspex to prevent concurrent logins for all accounts: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Put a check the "Faspex accounts" "Prevent concurrent login" check box.
- Select "Update" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56038r817914_chk'
  tag severity: 'medium'
  tag gid: 'V-252582'
  tag rid: 'SV-252582r817916_rule'
  tag stig_id: 'ASP4-FA-050180'
  tag gtitle: 'SRG-NET-000053-ALG-000001'
  tag fix_id: 'F-55988r817915_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
