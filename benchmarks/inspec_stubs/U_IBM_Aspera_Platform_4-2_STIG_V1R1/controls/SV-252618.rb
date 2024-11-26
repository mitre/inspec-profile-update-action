control 'SV-252618' do
  title 'The IBM Aspera High-Speed Transfer Endpoint must enable password protection of the node database.'
  desc 'Configuring the network element to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network element. Security-related parameters are those parameters impacting the security state of the network element, including the parameters required to satisfy other security control requirements. For the network element, security-related parameters include settings for network traffic management configurations.

System administrators can set a secure password for clients to authenticate with a Redis database. When the authorization layer is enabled, Redis refuses any query by unauthenticated clients. A client can authenticate itself by sending the AUTH command followed by the password.'
  desc 'check', 'Verify the IBM High-Speed Transfer Endpoint enables password protection of the node database with the following commands:

Initiate a cli connection to the node database.
$ sudo /opt/aspera/bin/asredis -p 31415
127.0.0.1:31415>

Type "info" in the cli to attempt to query the database.
127.0.0.1:31415>info
NOAUTH Authentication required.

If the command results do not state "Authentication required", this is a finding.'
  desc 'fix', 'Configure the IBM High-Speed Transfer Endpoint to enable password protection of the node database.

Temporarily change the ownership of the Redis configuration file aspera_31415.conf to the user asperadaemon with the following command:

$ sudo chown asperadaemon /opt/aspera/etc/Redis/aspera_31415.conf

Update the configuration file to save the password across reboots with the following commands:

$ sudo /opt/aspera/bin/asredis -p 31415
127.0.0.1:31415>CONFIG SET REQUIREPASS <password>
OK
127.0.0.1:31415>AUTH <password>
OK
127.0.0.1:31415>CONFIG REWRITE
OK
127.0.0.1:31415>quit

Restore aspera_31415.conf ownership to root with the following command:
$ sudo chown root /opt/aspera/etc/Redis/aspera_31415.conf

Create the node database password with the following command:

$ sudo /opt/aspera/bin/askmscli -s Redis-password

Store the node database password in the transfer user and asperadaemon keystores with the following commands:

$ sudo /opt/aspera/bin/askmscli -i -u <transferuser>
$ sudo /opt/aspera/bin/askmscli -i -u asperadaemon'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56074r818022_chk'
  tag severity: 'medium'
  tag gid: 'V-252618'
  tag rid: 'SV-252618r818024_rule'
  tag stig_id: 'ASP4-TE-030160'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag fix_id: 'F-56024r818023_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
