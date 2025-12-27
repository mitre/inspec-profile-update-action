control 'SV-82547' do
  title 'The A10 Networks ADC must terminate management sessions after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Review the device configuration.

The following command shows the terminal settings:
show terminal

If the idle-timeout is greater than 10 minutes or is set to zero (no timeout), this is a finding.

The following command shows the web management (GUI) settings:
show web-service

If the idle time is greater than 10 minutes or is set to zero (no timeout), this is a finding.'
  desc 'fix', 'The following command sets the terminal idle timeout to 10 minutes:
terminal idle-timeout 10

The following command sets the Web GUI timeout to 10 minutes:
web-service timeout-policy idle 10

Note: 10 minutes is the default setting.'
  impact 0.7
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68617r1_chk'
  tag severity: 'high'
  tag gid: 'V-68057'
  tag rid: 'SV-82547r1_rule'
  tag stig_id: 'AADC-NM-000070'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-74173r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
