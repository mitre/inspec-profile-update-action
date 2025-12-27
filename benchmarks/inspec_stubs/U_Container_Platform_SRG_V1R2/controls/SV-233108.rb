control 'SV-233108' do
  title 'The application must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity;'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'This requirement is NA for this technology.'
  desc 'fix', 'The requirement is NA. No fix is required.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36044r600811_chk'
  tag severity: 'medium'
  tag gid: 'V-233108'
  tag rid: 'SV-233108r754792_rule'
  tag stig_id: 'SRG-APP-000190-CTR-000500'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-36012r600812_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
