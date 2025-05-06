control 'SV-233149' do
  title 'Access to the container platform must display an explicit logout message to user indicating the reliable termination of authenticated communication sessions.'
  desc 'Access to the container platform will occur through web and terminal sessions. Any web interfaces must conform to application and web security requirements. Terminal access to the container platform and its components must provide a logout facility that terminates the connection to the component or the platform.'
  desc 'check', 'Review documentation and configuration settings to determine if the container platform displays a logout message. 

If the container platform does not display a logout message, this is a finding.'
  desc 'fix', 'Configure the container platform components to display an explicit logout message to users.'
  impact 0.3
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36085r600934_chk'
  tag severity: 'low'
  tag gid: 'V-233149'
  tag rid: 'SV-233149r879675_rule'
  tag stig_id: 'SRG-APP-000297-CTR-000705'
  tag gtitle: 'SRG-APP-000297'
  tag fix_id: 'F-36053r600935_fix'
  tag 'documentable'
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
