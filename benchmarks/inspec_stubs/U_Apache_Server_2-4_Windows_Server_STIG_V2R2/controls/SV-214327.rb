control 'SV-214327' do
  title 'The Apache web server must encrypt passwords during transmission.'
  desc 'Data used to authenticate, especially passwords, needs to be protected at all times, and encryption is the standard method for protecting authentication data during transmission. Data used to authenticate can be passed to and from the web server for many reasons.

Examples include data passed from a user to the web server through an HTTPS connection for authentication, the web server authenticating to a backend database for data retrieval and posting, and the web server authenticating to a clustered web server manager for an update.'
  desc 'check', %q(Review the <'INSTALL PATH'>\conf\httpd.conf file.

Ensure SSL is enabled by looking at the "SSLVerifyClient" directive.

If the value of "SSLVerifyClient" is not set to "require", this is a finding.)
  desc 'fix', %q(Edit the <'INSTALL PATH'>\conf\httpd.conf file and set the value of "SSLVerifyClient" to "require".

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15539r277484_chk'
  tag severity: 'medium'
  tag gid: 'V-214327'
  tag rid: 'SV-214327r505936_rule'
  tag stig_id: 'AS24-W1-000370'
  tag gtitle: 'SRG-APP-000172-WSR-000104'
  tag fix_id: 'F-15537r277485_fix'
  tag 'documentable'
  tag legacy: ['SV-102479', 'V-92391']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
