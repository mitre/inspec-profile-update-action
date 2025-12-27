control 'SV-220596' do
  title 'The Cisco switch must be configured to terminate all network connections associated with device management after five minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Review the Cisco switch configuration to verify that all network connections associated with a device management have an idle timeout value set to five minutes or less as shown in the example below:

ip http secure-server
ip http timeout-policy idle 300 life nnnn requests nn
…
…
…
line con 0
 exec-timeout 5 0
line vty 0 1
 exec-timeout 5 0

If the Cisco switch is not configured to terminate all network connections associated with a device management after five minutes of inactivity, this is a finding.'
  desc 'fix', 'Set the idle timeout value to five minutes or less on all configured login classes as shown in the example below:

SW1(config)#line vty 0 1
SW1(config-line)#exec-timeout 5 0
SW1(config-line)#exit
SW1(config)#line con 0
SW1(config-line)#exec-timeout 5 0
SW1(config-line)#exit
SW2(config)#ip http timeout-policy idle 300 life nnnn requests nn'
  impact 0.7
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22311r916302_chk'
  tag severity: 'high'
  tag gid: 'V-220596'
  tag rid: 'SV-220596r916304_rule'
  tag stig_id: 'CISC-ND-000720'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-22300r916303_fix'
  tag 'documentable'
  tag legacy: ['SV-110421', 'V-101317']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
