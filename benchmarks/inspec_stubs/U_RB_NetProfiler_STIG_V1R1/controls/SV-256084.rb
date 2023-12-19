control 'SV-256084' do
  title 'The Riverbed NetProfiler must be configured to terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level or deallocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Go to Configuration >> Appliance Security >> Password Security. 

Under "Inactivity Timeout", verify the "Enable Maximum Inactivity Timeout" box is checked and the timer is set for 10 minutes. 

If the inactivity timeout is not enabled, and/or the timer is not set to 10 minutes, this is a finding.'
  desc 'fix', 'Go to Configuration >> Appliance Security >> Password Security. 

Under "Inactivity Timeout", check the "Enable Maximum Inactivity Timeout" box and set the timer for 10 minutes.'
  impact 0.7
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59758r882758_chk'
  tag severity: 'high'
  tag gid: 'V-256084'
  tag rid: 'SV-256084r882760_rule'
  tag stig_id: 'RINP-DM-000042'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-59701r882759_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
