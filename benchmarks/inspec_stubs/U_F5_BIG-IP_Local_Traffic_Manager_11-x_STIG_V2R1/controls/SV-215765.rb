control 'SV-215765' do
  title 'The BIG-IP Core implementation must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system level network connection.

ALGs may provide session control functionality as part of content filtering, load balancing, or proxy services.'
  desc 'check', "Verify the BIG-IP Core is configured to terminate all network connections associated with a communications session at the end of the session as follows:

Verify a Protocol Profile is configured to terminate a session at the end of a specified time.

Navigate to the BIG-IP System manager >> Local Traffic >> Profiles >> Protocol >> TCP.

Select a profile for an in-band managed session.

Verify the TCP profile 'idle-timeout' is set to 600/900 seconds

Select a profile for a user session.

Verify the TCP profile 'idle-timeout' is set to 600/900 seconds

Verify the BIG-IP LTM is configured to use the Protocol Profile.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select appropriate virtual server.

Verify the TCP profile 'idle-timeout' is set to 600/900 seconds

If the BIG-IP Core is not configured to terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged sessions), the session must be terminated after 15 minutes of inactivity, this is a finding."
  desc 'fix', 'Configure BIG-IP Core to terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged sessions), the session must be terminated after 15 minutes of inactivity.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16957r291108_chk'
  tag severity: 'medium'
  tag gid: 'V-215765'
  tag rid: 'SV-215765r557356_rule'
  tag stig_id: 'F5BI-LT-000093'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag fix_id: 'F-16955r291109_fix'
  tag 'documentable'
  tag legacy: ['SV-74741', 'V-60311']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
