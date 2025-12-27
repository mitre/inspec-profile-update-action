control 'SV-206768' do
  title 'The Voice Video Endpoint must terminate all network connections associated with a communications session at the end of the session.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. Terminating network connections associated with communications sessions includes, de-allocating associated TCP/IP address/port pairs at the device or operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection.'
  desc 'check', 'Verify the Voice Video Endpoint terminates all network connections associated with a communications session at the end of the session. 

If the Voice Video Endpoint does not terminate all network connections associated with a communications session at the end of the session, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to terminate all network connections associated with a communications session at the end of the session.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7024r363827_chk'
  tag severity: 'high'
  tag gid: 'V-206768'
  tag rid: 'SV-206768r604140_rule'
  tag stig_id: 'SRG-NET-000213-VVEP-00028'
  tag gtitle: 'SRG-NET-000213'
  tag fix_id: 'F-7024r363828_fix'
  tag 'documentable'
  tag legacy: ['SV-81229', 'V-66739']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
