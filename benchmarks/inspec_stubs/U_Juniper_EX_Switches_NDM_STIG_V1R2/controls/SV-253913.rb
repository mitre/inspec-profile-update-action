control 'SV-253913' do
  title 'The Juniper EX switch must be configured to end all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Determine if the network device terminates the connection associated with a device management session at the end of the session or after 10 minutes of inactivity. This requirement may be verified by demonstration or configuration review. 

Junos permits the administrator to log out at the end of the session, which terminates the session and the network connection. Junos forcibly terminates the session and network connection upon exceeding the inactivity timeout threshold. Verify the global idle-timeout is 10 minutes. Alternately, verify that each login class is configured for an idle-timeout of 10.
[edit system login]
idle-timeout 10;
class <name> {
    idle-timeout 10; <<< Optional. If not configured, each login class inherits the global setting.
}

If the network device does not terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure the network device to terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity.

set system login idle-timeout 10'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57365r843770_chk'
  tag severity: 'high'
  tag gid: 'V-253913'
  tag rid: 'SV-253913r844264_rule'
  tag stig_id: 'JUEX-NM-000360'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-57316r843771_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
