control 'SV-240856' do
  title 'tc Server VCAC application, libraries, and configuration files must only be accessible to privileged users.'
  desc 'A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.'
  desc 'check', "At the command prompt, execute the following commands:

ls -alR /etc/vcac /usr/lib/vcac/server/webapps | grep -E '^-' | awk '$1 !~ /---$/ {print}'

If the command produces any output, this is a finding."
  desc 'fix', 'Remove all world permissions from any listed file with the following command:

chmod -R o-rwx /etc/vcac /usr/lib/vcac/server/webapps'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44089r674310_chk'
  tag severity: 'medium'
  tag gid: 'V-240856'
  tag rid: 'SV-240856r879753_rule'
  tag stig_id: 'VRAU-TC-000800'
  tag gtitle: 'SRG-APP-000380-WSR-000072'
  tag fix_id: 'F-44048r674311_fix'
  tag 'documentable'
  tag legacy: ['SV-100791', 'V-90141']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
