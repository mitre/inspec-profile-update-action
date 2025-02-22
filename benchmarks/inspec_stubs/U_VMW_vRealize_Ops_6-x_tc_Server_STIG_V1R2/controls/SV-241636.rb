control 'SV-241636' do
  title 'tc Server ALL must only contain services and functions necessary for operation.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system.

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Review the web server documentation and deployed configuration to determine if web server features, services, and processes are installed that are not needed for hosted application deployment.

If excessive features, services, and processes are installed, this is a finding.'
  desc 'fix', 'Uninstall or deactivate features, services, and processes not needed by the web server for operation.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44912r684145_chk'
  tag severity: 'medium'
  tag gid: 'V-241636'
  tag rid: 'SV-241636r879587_rule'
  tag stig_id: 'VROM-TC-000345'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-44871r683769_fix'
  tag 'documentable'
  tag legacy: ['SV-99557', 'V-88907']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
