control 'SV-246959' do
  title 'ONTAP must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Use "system timeout show" to see the session timeout in minutes.

If ONTAP does not terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure ONTAP to timeout idle sessions after 10 minutes with "system timeout modify -timeout 10".'
  impact 0.7
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50391r769207_chk'
  tag severity: 'high'
  tag gid: 'V-246959'
  tag rid: 'SV-246959r769209_rule'
  tag stig_id: 'NAOT-SC-000001'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-50345r769208_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
