control 'SV-252597' do
  title 'The IBM Aspera Shares interactive session must be terminated after 10 minutes of inactivity for non-privileged and privileged sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

'
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Shares interactive session are terminated after 10 minutes of inactivity for non-privileged and privileged sessions: 

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "Security" section.
- Select the "User Security" option.
- Verify the "Session timeout" option is set to "10" minutes or less.

If the "Session timeout" option is set to more than "10" minutes, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Shares interactive session to terminated after 10 minutes of inactivity for non-privileged and privileged sessions: 

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "Security" section.
- Select the User Security option.
- Edit the "Session timeout" option is set to "10" minutes or less.
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56053r817959_chk'
  tag severity: 'medium'
  tag gid: 'V-252597'
  tag rid: 'SV-252597r831509_rule'
  tag stig_id: 'ASP4-SH-060100'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag fix_id: 'F-56003r817960_fix'
  tag satisfies: ['SRG-NET-000213-ALG-000107', 'SRG-NET-000517-ALG-000006']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
