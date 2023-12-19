control 'SV-215833' do
  title 'The Cisco router must be configured to terminate all network connections associated with device management after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Review the Cisco router configuration to verify that all network connections associated with a device management have an idle timeout value set to 10 minutes or less as shown in the following example:

ip http secure-server
ip http timeout-policy idle 600 life nnnn requests nn
…
…
…
line con 0
 exec-timeout 10 0
line vty 0 1
 exec-timeout 10 0

If the Cisco router is not configured to terminate all network connections associated with a device management after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Set the idle timeout value to 10 minutes or less on all configured login classes as shown in the example below.

R1(config)#line vty 0 1
R1(config-line)#exec-timeout 10 0
R1(config-line)#exit
R1(config)#line con 0
R1(config-line)#exec-timeout 10 0
R1(config-line)#exit
R2(config)#ip http timeout-policy idle 600 life nnnn requests nn'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17072r835110_chk'
  tag severity: 'high'
  tag gid: 'V-215833'
  tag rid: 'SV-215833r879622_rule'
  tag stig_id: 'CISC-ND-000720'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-17070r835111_fix'
  tag 'documentable'
  tag legacy: ['SV-105409', 'V-96271']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
