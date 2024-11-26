control 'SV-240074' do
  title 'HAProxy must redirect all http traffic to use https.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements. 

vRA can be configured to redirect unencrypted, http port 80, traffic to use the encrypted, https port 443.'
  desc 'check', "At the command prompt, execute the following command:

grep 'redirect scheme https' /etc/haproxy/conf.d/20-vcac.cfg

Note: the command should return this line:

'redirect scheme https if !{ ssl_fc }'

If the command does not return the expected line, this is a finding."
  desc 'fix', %q(Navigate to and open /etc/haproxy/conf.d/20-vcac.cfg

Navigate to the "frontend https-in" section. 

In the "frontend https-in" section, add the 'redirect scheme https if !{ ssl_fc }' option before all 'acl' options.)
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43307r665389_chk'
  tag severity: 'high'
  tag gid: 'V-240074'
  tag rid: 'SV-240074r879692_rule'
  tag stig_id: 'VRAU-HA-000335'
  tag gtitle: 'SRG-APP-000315-WSR-000003'
  tag fix_id: 'F-43266r665390_fix'
  tag 'documentable'
  tag legacy: ['SV-99835', 'V-89185']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
