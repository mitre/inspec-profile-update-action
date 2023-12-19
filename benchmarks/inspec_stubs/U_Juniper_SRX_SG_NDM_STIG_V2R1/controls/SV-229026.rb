control 'SV-229026' do
  title 'The Juniper SRX Services Gateway must specify the order in which authentication servers are used.'
  desc 'Specifying an authentication order implements an authentication, authorization, and accounting methods list to be used, thus allowing the implementation of redundant or backup AAA servers. These commands also ensure that a default method or order will not be used by the device (e.g., local passwords).

The Juniper SRX must specify the order in which authentication is attempted by including the authentication-order statement in the authentication server configuration. 

Remote logon using password results in a CAT 1 finding (CCI-000765) for failure to use two-factor authentication. Thus, if the account of last resort uses only password authentication, this configuration prevents remote access. DoD policy is that redundant AAA servers are required to mitigate the risk of a failure of the primary AAA device.'
  desc 'check', 'Verify a RADIUS or TACACS+ server order has been configured.

From operational mode enter the command:
show system authentication-order

If the authentication-order for either or both RADIUS or TACACS+ server order has not been configured, this is a finding.

If the authentication-order includes the password method, this is a finding.'
  desc 'fix', 'Add an external RADIUS or TACACS+ server, and specify the port number and shared secret of the server. Remote logon using password results in a CAT 1 finding (CCI-000765) for failure to use two-factor authentication. Thus, if the account of last resort uses only password authentication, this configuration prevents remote access. DoD policy is that redundant AAA servers are required to mitigate the risk of a failure of the primary AAA device.

[edit]
set system authentication-order tacplus

or 

[edit]
set system authentication-order radius

From operational mode enter the command:
show system authentication-order

If password is set as an option, remove this command from the configuration.
[edit]
delete system authentication-order password'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-31341r518254_chk'
  tag severity: 'low'
  tag gid: 'V-229026'
  tag rid: 'SV-229026r518256_rule'
  tag stig_id: 'JUSX-DM-000098'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31318r518255_fix'
  tag 'documentable'
  tag legacy: ['SV-81087', 'V-66597']
  tag cci: ['CCI-000366', 'CCI-000371']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
