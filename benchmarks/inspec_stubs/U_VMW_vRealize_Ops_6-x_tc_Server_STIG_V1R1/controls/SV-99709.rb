control 'SV-99709' do
  title 'tc Server API application, libraries, and configuration files must only be accessible to privileged users.'
  desc 'A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.'
  desc 'check', "At the command prompt, execute the following commands:

cd /usr/lib/vmware-vcops/tomcat-enterprise

ls -alR bin conf | grep -E '^-' |  awk '$1 !~ /---$/ {print}'

If the command produces any output, this is a finding."
  desc 'fix', 'At the command prompt, execute the following command:

Note: Replace <file_name> for the name of the file that was returned.

If the file was found in “/bin” or “/lib”, execute the following command:

chmod 700 <file_name>

If the file was found in “/conf”, execute the following command:

chmod 600 <file_name>

Repeat the command for each file that was returned'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89059'
  tag rid: 'SV-99709r1_rule'
  tag stig_id: 'VROM-TC-000840'
  tag gtitle: 'SRG-APP-000380-WSR-000072'
  tag fix_id: 'F-95801r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
