control 'SV-207557' do
  title 'On the BIND 9.x server the platform on which the name server software is hosted must be configured to send outgoing DNS messages from a random port.'
  desc "Hosts that run the name server software should not provide any other services and therefore should be configured to respond to DNS traffic only. Outgoing DNS messages should be sent from a random port to minimize the risk of an attacker's guessing the outgoing message port and sending forged replies."
  desc 'check', 'Verify that the BIND 9.x server does not limit outgoing DNS messages to a specific port.

Inspect the "named.conf" file for the any instance of the "port" flag:

options {
listen-on port 53 { <ip_address>; };
listen-on-v6 port 53 { <ip_v6_address>; };
};

If any "port" flag is found outside of the "listen-on" or "listen-on-v6" statements, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Configure the BIND 9.x server to only use the "port" flag with the "listen-on" and "listen-on-v6" statements:

options {
listen-on port 53 { <ip_address>; };
listen-on-v6 port 53 { <ip_v6_address>; };
};

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7812r283725_chk'
  tag severity: 'low'
  tag gid: 'V-207557'
  tag rid: 'SV-207557r612253_rule'
  tag stig_id: 'BIND-9X-001059'
  tag gtitle: 'SRG-APP-000516-DNS-000110'
  tag fix_id: 'F-7812r283726_fix'
  tag 'documentable'
  tag legacy: ['SV-87043', 'V-72419']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
