control 'SV-202074' do
  title 'The network device must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after five minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Determine if the network device terminates the connection associated with a device management session at the end of the session or after five minutes of inactivity. This requirement may be verified by demonstration or configuration review. If the network device does not terminate the connection associated with a device management session at the end of the session or after five minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure the network device to terminate the connection associated with a device management session at the end of the session or after five minutes of inactivity.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2200r916340_chk'
  tag severity: 'high'
  tag gid: 'V-202074'
  tag rid: 'SV-202074r916342_rule'
  tag stig_id: 'SRG-APP-000190-NDM-000267'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-2201r916341_fix'
  tag 'documentable'
  tag legacy: ['SV-69405', 'V-55159']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
