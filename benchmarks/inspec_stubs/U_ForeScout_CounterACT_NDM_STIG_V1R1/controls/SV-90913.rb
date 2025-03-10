control 'SV-90913' do
  title 'CounterACT must terminate all network connections associated with an Enterprise Manager Console session upon Exit, or session disconnection, or after 10 minutes of inactivity, except where prevented by documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level or deallocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'CounterACT is inherently designed to terminate upon Exit or session disconnection, thus this part of the requirement does not have to be verified. To verify the device is configured to terminate management sessions after "10" minutes of inactivity, verify the timeout value is configured.

1. On the Enterprise Manager Console.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the "User Inactivity Timeout" check box is selected and the associated setting is set to "10" minutes.

If applicable, verify exceptions to this requirement are documented and signed.

If Counteract does not terminate the connection associated with an Enterprise Manager Console at the end of the session or after "10" minutes of inactivity, this is a finding.'
  desc 'fix', 'CounterACT is inherently designed to terminate upon Exit or session disconnection, thus this part of the requirement does not have a fix. To configure CounterACT to terminate the connection after "10" minutes of inactivity perform the following steps.

1. On the Enterprise Manager Console.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Ensure the "User In-activity Timeout" check box is selected and the associated setting is set to "10 minutes.

If exceptions to this requirement are necessary based on mission requirements, document the mission requirement and validate with a signature by a designated authority.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75911r2_chk'
  tag severity: 'medium'
  tag gid: 'V-76225'
  tag rid: 'SV-90913r1_rule'
  tag stig_id: 'CACT-NM-000001'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-82861r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
