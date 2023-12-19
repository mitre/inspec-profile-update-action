control 'SV-79615' do
  title 'The DataPower Gateway must display an explicit logout message to administrators indicating the reliable termination of authenticated communications sessions.'
  desc 'If an explicit logout message is not displayed and the administrator does not expect to see one, the administrator may inadvertently leave a management session un-terminated. The session may remain open and be exploited by an attacker; this is referred to as a zombie session. Administrators need to be aware of whether or not the session has been terminated.'
  desc 'check', 'To verify, log out of a web session and an SSH command line session.

Upon logout from the web interface, the DataPower Gateway displays the IBM DataPower Login panel. This is a clear indication that the administrator has logged out. 

Upon logout from an administrative SSH command line session, the following message is displayed: "Unauthorized access prohibited. logon:" A clear indication that logout has occurred.

If this message is not present, this is a finding.'
  desc 'fix', 'Configure the DataPower Gateway to use a custom user interface XML file that can be configured to provide the desired logout message to administrators. 

From the WebGUI, go to Administration >> Device >> System Settings and associate the custom interface file with the "Customer User Interface" field. 

A template of the custom user interface file may be found on the DataPower file system at store:///schemas/dp-user-interface.xsd.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65753r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65125'
  tag rid: 'SV-79615r1_rule'
  tag stig_id: 'WSDP-NM-000083'
  tag gtitle: 'SRG-APP-000297-NDM-000281'
  tag fix_id: 'F-71065r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
