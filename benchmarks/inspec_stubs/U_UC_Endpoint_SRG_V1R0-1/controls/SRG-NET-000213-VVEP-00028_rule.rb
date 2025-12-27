control 'SRG-NET-000213-VVEP-00028_rule' do
  title 'The Unified Communications Endpoint must be configured to terminate all network connections associated with a communications session at the end of the session.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. 

This requirement applies to any network element that tracks individual sessions (e.g., stateful inspection firewall, ALG, or VPN).'
  desc 'check', 'Verify the Unified Communications Endpoint terminates all network connections associated with a communications session at the end of the session. 

If the Unified Communications Endpoint does not terminate all network connections associated with a communications session at the end of the session, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to terminate all network connections associated with a communications session at the end of the session.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000213-VVEP-00028_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000213-VVEP-00028'
  tag rid: 'SRG-NET-000213-VVEP-00028_rule'
  tag stig_id: 'SRG-NET-000213-VVEP-00028'
  tag gtitle: 'SRG-NET-000213-VVEP-00028'
  tag fix_id: 'F-SRG-NET-000213-VVEP-00028_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
