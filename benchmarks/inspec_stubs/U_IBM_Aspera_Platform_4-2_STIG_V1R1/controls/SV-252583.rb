control 'SV-252583' do
  title 'IBM Aspera Faspex must require password complexity features to be enabled.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Faspex requires password complexity: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Verify the "Faspex accounts" "Use strong passwords" option is checked.

If the "Use strong passwords" option is not checked, this is a finding.

If the "Use strong passwords" option is checked, downgrade this requirement to a CAT III.'
  desc 'fix', 'Configure IBM Aspera Faspex to require password complexity: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Put a check the "Faspex accounts" "Use strong passwords" check box.
- Select "Update" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56039r817917_chk'
  tag severity: 'medium'
  tag gid: 'V-252583'
  tag rid: 'SV-252583r818123_rule'
  tag stig_id: 'ASP4-FA-050190'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55989r817918_fix'
  tag 'documentable'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-001620']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (3)']
end
