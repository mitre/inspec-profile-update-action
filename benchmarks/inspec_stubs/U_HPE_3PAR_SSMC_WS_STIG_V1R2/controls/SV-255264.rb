control 'SV-255264' do
  title 'SSMC web server application, libraries, and configuration files must only be accessible to privileged users.'
  desc 'A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.

'
  desc 'check', 'Verify that SSMC is configured to protect web server configuration files and logs from unauthorized access by executing command that enables stricter file permission:

$ sudo /ssmc/bin/config_security.sh -o strict_file_permission -a status
Strict file permission is set

If the output does not read "Strict file permission is set", this is a finding.'
  desc 'fix', 'Configure SSMC to protect web server configuration files and logs from unauthorized access by executing command that enables stricter file permission (cannot be undone): 

$ sudo /ssmc/bin/config_security.sh -f -o strict_file_permission -a set'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58877r869959_chk'
  tag severity: 'medium'
  tag gid: 'V-255264'
  tag rid: 'SV-255264r879613_rule'
  tag stig_id: 'SSMC-WS-020000'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-58821r869960_fix'
  tag satisfies: ['SRG-APP-000176-WSR-000096', 'SRG-APP-000380-WSR-000072', 'SRG-APP-000211-WSR-000030']
  tag 'documentable'
  tag cci: ['CCI-000186', 'CCI-001082', 'CCI-001813']
  tag nist: ['IA-5 (2) (a) (1)', 'SC-2', 'CM-5 (1) (a)']
end
