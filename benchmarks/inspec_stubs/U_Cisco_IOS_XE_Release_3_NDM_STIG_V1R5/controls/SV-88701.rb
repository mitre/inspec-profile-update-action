control 'SV-88701' do
  title 'The Cisco IOS XE router must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to support session time outs and idle time outs on all management interfaces.

The configuration should look similar to the example below:

line con 0
 exec-timeout 10 0
 
line vty 0 5
 exec-timeout 10 0

If it is not configured to support session idle time outs on all management interfaces, this is a finding.'
  desc 'fix', 'Configure session time outs and idle time outs on all management interfaces using the following commands:

line con 0
 exec-timeout 10 0
 
line vty 0 5
 exec-timeout 10 0'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74117r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74027'
  tag rid: 'SV-88701r2_rule'
  tag stig_id: 'CISR-ND-000071'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-80569r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
