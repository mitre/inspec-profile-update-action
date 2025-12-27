control 'SV-240061' do
  title 'HAProxy frontend servers must be bound to a specific port.'
  desc 'The web server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server. If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.

Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', 'Navigate to and open the following files:

/etc/haproxy/conf.d/20-vcac.cfg
/etc/haproxy/conf.d/30-vro-config.cfg

Verify that each frontend is bound to at least one port. Below is an example binding:

frontend https-in-vro-config
    bind :8283

If each frontend is not bound to at least one port, this is a finding.'
  desc 'fix', 'Navigate to and open the following files:

/etc/haproxy/conf.d/20-vcac.cfg
/etc/haproxy/conf.d/30-vro-config.cfg

Configure each frontend to be bound to at least one port.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43294r665350_chk'
  tag severity: 'medium'
  tag gid: 'V-240061'
  tag rid: 'SV-240061r879588_rule'
  tag stig_id: 'VRAU-HA-000185'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-43253r665351_fix'
  tag 'documentable'
  tag legacy: ['SV-99809', 'V-89159']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
