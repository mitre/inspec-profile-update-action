control 'SV-89653' do
  title 'The SSH CLI of the MQ Appliance network device must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level or deallocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
rbm 
show 

If the idle-timeout value is not 600 seconds or less, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
rbm 
idle-timeout <600 seconds or less> 
exit 
write mem 
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74979'
  tag rid: 'SV-89653r1_rule'
  tag stig_id: 'MQMH-ND-000760'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-81595r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
