control 'SV-252563' do
  title 'IBM Aspera Console interactive session must be terminated after 10 minutes of inactivity for non-privileged and privileged sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

'
  desc 'check', 'Verify IBM Aspera Console interactive sessions are terminated after 10 minutes of inactivity for non-privileged and privileged sessions: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Security" section.
- Verify the "Session timeout" option is set to "10" minutes or less.

If the "Session Timeout" option is set to more than "10" minutes, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Console interactive sessions to terminate after 10 minutes of inactivity for non-privileged and privileged sessions: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege.
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Security" section.
- Edit the "Session Timeout" option to "10" minutes or less.
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56019r817857_chk'
  tag severity: 'medium'
  tag gid: 'V-252563'
  tag rid: 'SV-252563r817859_rule'
  tag stig_id: 'ASP4-CS-040160'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag fix_id: 'F-55969r817858_fix'
  tag satisfies: ['SRG-NET-000213-ALG-000107', 'SRG-NET-000517-ALG-000006']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
