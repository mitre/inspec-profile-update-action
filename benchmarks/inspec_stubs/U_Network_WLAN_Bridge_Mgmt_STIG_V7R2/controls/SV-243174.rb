control 'SV-243174' do
  title 'The network device must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. Quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level or deallocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Review the management connection for administrative access and verify the network device is configured to time-out the connection at 10 minutes or less of inactivity.

If the device does not terminate inactive management connections at 10 minutes or less, this is a finding.'
  desc 'fix', 'Configure the network devices to ensure the timeout for unattended administrative access connections is no longer than 10 minutes.'
  impact 0.7
  ref 'DPMS Target Network WLAN Bridge Mgmt'
  tag check_id: 'C-46449r719975_chk'
  tag severity: 'high'
  tag gid: 'V-243174'
  tag rid: 'SV-243174r916342_rule'
  tag stig_id: 'WLAN-ND-000500'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-46406r719976_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
