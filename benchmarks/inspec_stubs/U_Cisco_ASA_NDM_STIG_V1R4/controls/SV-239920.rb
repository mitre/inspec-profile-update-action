control 'SV-239920' do
  title 'The Cisco ASA must be configured to terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Review the Cisco ASA configuration to verify all network connections associated with a device management have an idle timeout value set to 10 minutes or less as shown in the following example:

http server idle-timeout 10
…
…
…
ssh timeout 10
…
…
…
console timeout 10

If the Cisco ASA is not configured to terminate all network connections associated with a device management after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Set the idle timeout value to 10 minutes or less for console, ssh, and http (if ASDM is used) access.

SW1(config)# ssh timeout 10
SW1(config)# console timeout 10
ASA(config)# http server idle-timeout 10
SW1(config)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43153r666121_chk'
  tag severity: 'high'
  tag gid: 'V-239920'
  tag rid: 'SV-239920r879622_rule'
  tag stig_id: 'CASA-ND-000690'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-43112r666122_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
