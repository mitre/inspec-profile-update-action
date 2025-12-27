control 'SV-89423' do
  title 'The MQ Appliance WebGUI interface to the messaging server must prohibit the use of cached authenticators after one hour.'
  desc 'When the messaging server is using PKI authentication, a local revocation cache must be stored for instances when the revocation cannot be authenticated through the network, but if cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'Display the SSL Server Profile associated with the WebGUI using the (CLI).

Log on as an admin to the MQ appliance using SSH terminal access.

Enter:
co
show web-mgmt

To note the name of the ssl-server, enter:
crypto
ssl-server <ssl-server name>
show

Verify the following are displayed:
caching on
cache-timeout 3600

If the ssl-server configuration does not exist, or if caching is "off", or if the cache-timeout setting does not equal “3600” seconds (60 minutes),  this is a finding.'
  desc 'fix', 'Display the SSL Server Profile associated with the WebGUI (CLI).
Enter:
co
show web-mgmt

[Note the name of the ssl-server]

Define the cache parameters of the SSL Server using the CLI.
Enter:
co
crypto
ssl-server <ssl-server name>
caching on
cache-timeout <3600>
exit
exit
write mem
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74605r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74749'
  tag rid: 'SV-89423r1_rule'
  tag stig_id: 'MQMH-AS-000190'
  tag gtitle: 'SRG-APP-000400-AS-000246'
  tag fix_id: 'F-81365r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
