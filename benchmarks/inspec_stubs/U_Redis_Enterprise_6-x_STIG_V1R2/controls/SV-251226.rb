control 'SV-251226' do
  title 'Redis Enterprise DBMS must enforce authorized access to all PKI private keys stored/used by Redis Enterprise DBMS.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder. In cases where the DBMS-stored private keys are used to authenticate the DBMS to the system's clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man-in-the-middle attacks against the DBMS system and its clients.

Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 or 140-3 validated cryptographic modules.

All access to the private key(s) of the DBMS must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of the DBMS's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions."
  desc 'check', "All keys must be stored by the host RHEL OS that Redis Enterprise resides on. On the server, look for proxy_cert.pem found in /etc/opt/redislabs. If proxy_cert.pem has file permissions that would allow unauthorized users to access it, this is a finding. 

Keys can also be manipulated on the Redis Enterprise UI. RBAC prevents unauthorized users from doing this; to check:

Review organization documentation to determine which users should have administrative privileges. From there:
1. Log in to Redis Enterprise UI as a user in the administrator role.
2. Navigate to the Access Control tab.
3. Compare the documented users to the users found in the user settings on the web UI.

If any users have administrative privileges and are not documented, this is a finding. 

If access to the DBMS's private key(s) is not restricted to authenticated and authorized users, this is a finding."
  desc 'fix', 'Apply or modify access controls and permissions (in the file system/operating system) to tools used to view or modify where the certificates are stored. Tools must be accessible by authorized personnel only.

/etc/opt/redislabs (or wherever the organizationally defined location for certificates are stored) should have an appropriate and documented admin user and group owner and the directory should not have permissions more than 700. 

To update these permissions, run the following commands:
chown redislabs:redislabs /etc/opt/redislabs
chmod 700 /etc/opt/redislabs/proxy_cert.pem'
  impact 0.7
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54661r804866_chk'
  tag severity: 'high'
  tag gid: 'V-251226'
  tag rid: 'SV-251226r863361_rule'
  tag stig_id: 'RD6X-00-009200'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-54615r804867_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
