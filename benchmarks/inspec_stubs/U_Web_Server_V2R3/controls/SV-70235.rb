control 'SV-70235' do
  title 'The web server application, libraries, and configuration files must only be accessible to privileged users.'
  desc 'A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.'
  desc 'check', 'Review the web server documentation and configuration to determine if the web server provides unique account roles specifically for the purposes of segmenting the responsibilities for managing the web server.

Log into the hosting server using a web server role with limited permissions (e.g., Auditor, Developer, etc.) and verify the account is not able to perform configuration changes that are not related to that role.

If roles are not defined with limited permissions and restrictions, this is a finding.'
  desc 'fix', 'Define roles and responsibilities to be used when managing the web server.

Configure the hosting system to utilize specific roles that restrict access related to web server system and configuration changes.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-56551r2_chk'
  tag severity: 'medium'
  tag gid: 'V-55981'
  tag rid: 'SV-70235r2_rule'
  tag stig_id: 'SRG-APP-000380-WSR-000072'
  tag gtitle: 'SRG-APP-000380-WSR-000072'
  tag fix_id: 'F-60859r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
