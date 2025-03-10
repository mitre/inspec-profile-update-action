control 'SV-100791' do
  title 'tc Server VCAC application, libraries, and configuration files must only be accessible to privileged users.'
  desc 'A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.'
  desc 'check', "At the command prompt, execute the following commands:

ls -alR /etc/vcac /usr/lib/vcac/server/webapps | grep -E '^-' | awk '$1 !~ /---$/ {print}'

If the command produces any output, this is a finding."
  desc 'fix', 'Remove all world permissions from any listed file with the following command:

chmod -R o-rwx /etc/vcac /usr/lib/vcac/server/webapps'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89833r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90141'
  tag rid: 'SV-100791r1_rule'
  tag stig_id: 'VRAU-TC-000800'
  tag gtitle: 'SRG-APP-000380-WSR-000072'
  tag fix_id: 'F-96883r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
