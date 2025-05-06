control 'SV-220493' do
  title 'The Cisco switch must be configured to terminate all network connections associated with device management after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Review the Cisco switch configuration to verify that all network connections associated with a device management have an idle timeout value set to 10 minutes or less as shown in the following example:

line console
 exec-timeout 10 
line vty 
 exec-timeout 10 

If the Cisco switch is not configured to terminate all network connections associated with a device management after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Set the idle timeout value to 10 minutes or less on all configured login classes as shown in the example below:

SW1(config)# line console
SW1(config-console)# exec-timeout 10 
SW1(config-console)# exit
SW1(config)# line vty
SW1(config-line)# exec-timeout 10'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22208r539200_chk'
  tag severity: 'high'
  tag gid: 'V-220493'
  tag rid: 'SV-220493r604141_rule'
  tag stig_id: 'CISC-ND-000720'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-22197r539201_fix'
  tag 'documentable'
  tag legacy: ['SV-110635', 'V-101531']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
