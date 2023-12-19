control 'SV-240080' do
  title 'HAProxy libraries, and configuration files must only be accessible to privileged users.'
  desc 'A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.'
  desc 'check', 'At the command prompt, execute the following command:
 
ls -alR /etc/haproxy /etc/init.d/haproxy /usr/sbin/haproxy
 
If any configuration or application files have permissions greater than "750" or are not owned by "root", this is a finding.'
  desc 'fix', 'Navigate to any listed files with incorrect permissions or ownership and set them in accordance with site policy.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43313r665407_chk'
  tag severity: 'medium'
  tag gid: 'V-240080'
  tag rid: 'SV-240080r879753_rule'
  tag stig_id: 'VRAU-HA-000390'
  tag gtitle: 'SRG-APP-000380-WSR-000072'
  tag fix_id: 'F-43272r665408_fix'
  tag 'documentable'
  tag legacy: ['SV-99847', 'V-89197']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
