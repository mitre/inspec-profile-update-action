control 'SV-75315' do
  title 'The Arista Multilayer Switch must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Determine if the network device terminates the connection associated with a device management session at the end of the session or after 10 minutes of inactivity. This requirement may be verified by demonstration or configuration review.

Verify by executing a "show running-config" command, and under the "management ssh" subsection, validate the configuration statement "idle-timeout 10" is present and the value is 10 or less.

If the network device does not terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure the network device to terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity.

Arista switches have a configurable timeout function that automatically closes connections to the switch upon reaching an organization-defined period of time.

Configuration Example:

switch(config)#management ssh
switch(config-mgmt-ssh)#idle-timeout 10

Configure the switch to terminate an idle ssh connection after 10 minutes of inactivity.'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61805r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60857'
  tag rid: 'SV-75315r1_rule'
  tag stig_id: 'AMLS-NM-000240'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-66569r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
