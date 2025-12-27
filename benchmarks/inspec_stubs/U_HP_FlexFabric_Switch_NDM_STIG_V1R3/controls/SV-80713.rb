control 'SV-80713' do
  title 'The HP FlexFabric Switch must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Determine if the HP FlexFabric Switch terminates the connection associated with a device management session at the end of the session or after 10 minutes of inactivity.

If the HP FlexFabric Switch does not terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity:

[HP] user-interface vty 0 63
[HP-line-vty0-63] idle-timeout 10'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66869r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66223'
  tag rid: 'SV-80713r1_rule'
  tag stig_id: 'HFFS-ND-000069'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-72299r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
