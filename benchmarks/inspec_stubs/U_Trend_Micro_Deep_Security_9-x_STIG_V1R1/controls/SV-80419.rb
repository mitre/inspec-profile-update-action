control 'SV-80419' do
  title 'Trend Deep Security must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity, except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure all network connections associated with a communications session are terminated at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity, except to fulfill documented and validated mission requirements.

If the value for user session termination under the Administration >> System Settings >> Security >> Session timeout, is not set to 10 minutes, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity, except to fulfill documented and validated mission requirements.

Configure the policy value for session timeout. Under the Administration >> System Settings >> Security, set the value for “Session timeout” to 10 minutes.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66577r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65929'
  tag rid: 'SV-80419r1_rule'
  tag stig_id: 'TMDS-00-000175'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-72005r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
