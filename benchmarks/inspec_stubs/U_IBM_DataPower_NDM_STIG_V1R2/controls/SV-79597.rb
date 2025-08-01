control 'SV-79597' do
  title 'The DataPower Gateway must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Using the DataPower WebGUI: 
In the search field, enter Web Management, 
From the search results, click Web Management Service, 
In the Idle timeout field, check to ensure that the value entered in no greater than 600 (the number of seconds after which the appliance closes the connection).
If the number is greater than 600, this is a finding.'
  desc 'fix', 'Using the DataPower WebGUI: 
In the search field, enter Web Management, 
From the search results, click Web Management Service, 
In the Idle timeout field, enter 600 (the number of seconds after which the appliance closes the connection).'
  impact 0.7
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65735r1_chk'
  tag severity: 'high'
  tag gid: 'V-65107'
  tag rid: 'SV-79597r1_rule'
  tag stig_id: 'WSDP-NM-000069'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-71047r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
