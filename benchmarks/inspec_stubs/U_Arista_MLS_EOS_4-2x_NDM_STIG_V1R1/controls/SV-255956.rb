control 'SV-255956' do
  title 'The Arista network device must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

'
  desc 'check', 'Verify the Arista device is configured for 10-minute inactivity timeout for management sessions.

switch#sh run | section management
!
interface Management1
   ip address 172.28.134.55/20
!
management console
idle-timeout 10
!
management ssh
   idle-timeout 10
!

If the Arista network device is not configured to terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure the Arista network device to terminate the connections after 10 minutes of inactivity.

Step 1: Configure the settings for the console.

switch(config)#management console
switch(config-mgmt-console)#idle-timeout 10
switch(config-mgmt-console)#exit
switch(config)#
!

Step 2: Configure the settings for SSH.

switch(config)#management ssh
switch(config-mgmt-ssh)#idle-timeout 10
switch(config-mgmt-console)#exit
switch(config)#
!'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59632r882208_chk'
  tag severity: 'high'
  tag gid: 'V-255956'
  tag rid: 'SV-255956r882210_rule'
  tag stig_id: 'ARST-ND-000490'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-59575r882209_fix'
  tag satisfies: ['SRG-APP-000190-NDM-000267', 'SRG-APP-000186-NDM-000266']
  tag 'documentable'
  tag cci: ['CCI-000879', 'CCI-001133']
  tag nist: ['MA-4 e', 'SC-10']
end
