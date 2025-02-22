control 'SV-240258' do
  title 'Lighttpd must be configured to utilize the Common Information Model Object Manager.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements.

As the web server for the vRA Virtual Appliance Management Interface (vAMI), Lighttpd is the primary remote access management system for vRA. vRA uses CIMOM to Authenticate the sysadmin and to enforce policy requirements.'
  desc 'check', %q(At the command prompt, execute the following command:    

cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/cimom/,/}/'

Note:  The return value should produce the following output:

$HTTP["url"] =~ "^/cimom" {
    proxy.server = ( "" =>
                    ((
                      "host" => "127.0.0.1",
                      "port" => "5488"
                    ))
                   )
}

If the return value does not match the above output, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the lighttpd.conf with the following:

$HTTP["url"] =~ "^/cimom" {
    proxy.server = ( "" =>
                    ((
                      "host" => "127.0.0.1",
                      "port" => "5488"
                    ))
                   )
}'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43491r854812_chk'
  tag severity: 'high'
  tag gid: 'V-240258'
  tag rid: 'SV-240258r879692_rule'
  tag stig_id: 'VRAU-LI-000370'
  tag gtitle: 'SRG-APP-000315-WSR-000003'
  tag fix_id: 'F-43450r854813_fix'
  tag 'documentable'
  tag legacy: ['SV-99947', 'V-89297']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
