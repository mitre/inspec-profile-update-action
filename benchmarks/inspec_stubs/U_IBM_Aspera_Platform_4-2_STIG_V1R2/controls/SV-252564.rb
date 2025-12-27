control 'SV-252564' do
  title 'IBM Aspera Console must enforce password complexity by requiring at least fifteen characters, with at least one upper case letter, one lower case letter, one number, and one symbol.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.'
  desc 'check', 'Verify IBM Aspera Console enforces password complexity by requiring at least 15 characters, with at least one uppercase letter, one lowercase letter, one number, and one symbol: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Console Password Options" section.
- Verify the "Password Requirement Regular Expression" has the following value: (?=.*\\d)(?=.*([a-z]))(?=.*([A-Z]))(?=.*(\\W|_)).{15,}
- Verify the "Password Requirement Message" has the following text: "Passwords must be at least fifteen characters long, with at least one upper case letter, one lower case letter, one number, and one symbol".

If the "Password Requirement Regular Expression" value is not "(?=.*\\d)(?=.*([a-z]))(?=.*([A-Z]))(?=.*(\\W|_)).{15,}", this is a finding.

If the "Password Requirement Message" value is not "Passwords must be at least fifteen characters long, with at least one upper case letter, one lower case letter, one number, and one symbol", this is a finding.'
  desc 'fix', 'Configure IBM Aspera Console to enforce password complexity by requiring at least 15 characters, with at least one uppercase letter, one lowercase letter, one number, and one symbol: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Console Password Options" section.
- Edit the "Password Requirement Regular Expression" with the following value: (?=.*\\d)(?=.*([a-z]))(?=.*([A-Z]))(?=.*(\\W|_)).{15,}
- Edit the "Password Requirement Message" with the following text: "Passwords must be at least fifteen characters long, with at least one upper case letter, one lower case letter, one number, and one symbol".
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56020r817860_chk'
  tag severity: 'medium'
  tag gid: 'V-252564'
  tag rid: 'SV-252564r817862_rule'
  tag stig_id: 'ASP4-CS-040170'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55970r817861_fix'
  tag 'documentable'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000205', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']
end
