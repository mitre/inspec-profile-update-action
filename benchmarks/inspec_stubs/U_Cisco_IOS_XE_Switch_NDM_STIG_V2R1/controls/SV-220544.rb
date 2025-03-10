control 'SV-220544' do
  title 'The Cisco switch must be configured to terminate all network connections associated with device management after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Review the Cisco switch configuration to verify that all network connections associated with a device management have an idle timeout value set to 10 minutes or less as shown in the following example:

ip http secure-server
ip http timeout-policy idle 600 life nnnn requests nn
…
…
…
line con 0
 exec-timeout 10 0
line vty 0 4
 exec-timeout 10 0

If the Cisco switch is not configured to terminate all network connections associated with a device management after "10" minutes of inactivity, this is a finding.'
  desc 'fix', 'Set the idle timeout value to "10" minutes or less on all configured login classes as shown in the example below:

SW1(config)#line vty 0 4
SW1(config-line)#exec-timeout 10 0
SW1(config-line)#exit
SW1(config)#line con 0
SW1(config-line)#exec-timeout 10 0
SW1(config-line)#exit
SW2(config)#ip http timeout-policy idle 600 life nnnn requests nn'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22259r508576_chk'
  tag severity: 'high'
  tag gid: 'V-220544'
  tag rid: 'SV-220544r531084_rule'
  tag stig_id: 'CISC-ND-000720'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-22248r508577_fix'
  tag 'documentable'
  tag legacy: ['V-101439', 'SV-110543']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
