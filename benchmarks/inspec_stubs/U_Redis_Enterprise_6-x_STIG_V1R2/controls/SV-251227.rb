control 'SV-251227' do
  title 'Redis Enterprise DBMS must map the PKI-authenticated identity to an associated user account.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates. Once a PKI certificate has been validated, it must be mapped to a DBMS user account for the authenticated identity to be meaningful to the DBMS and useful for authorization decisions.'
  desc 'check', 'Review the Redis Enterprise configuration to verify user accounts are being mapped directly to unique identifying information within the validated PKI certificate.

To test, have the user log in to the database and verify that the unique certificate to the authenticating user is used or prompted. If user accounts are not being mapped to authenticated identities, this is a finding.'
  desc 'fix', 'Configure Redis Enterprise settings to meet organizationally defined requirements. Redis Enterprise uses LDAP to map authenticated identity directly to the DBMS user account.

1. Before enabling LDAP in Redis Software, it is important to verify:
- Confirmation of the LDAP groups that correspond to the levels of access on which to authorize. Each LDAP group will be mapped to a Redis Software access control role.
- Confirmation of Redis Software access control role for each LDAP group. If role-based access controls (RBAC) have not already been set up, do so before enabling LDAP.

2. The following LDAP info is needed:
- Server URI, including host, port, and protocol details.
- Certificate details for secure protocols.
- Bind credentials, including Distinguished Name, password, and (optionally) client public and private keys for certificate authentication.
- Authentication query details, whether template or query.
- Authorization query details, whether attribute or query.
- The Distinguished Names of LDAP groups that will be used to authorize access to Redis Software resources.

3. Use Settings | LDAP to enable LDAP access.

4. Map LDAP groups to access control roles.

5. Update database access control lists (ACLs) to authorize role access. 
If appropriate roles are already established, update them to include LDAP groups.

For additional information:
https://docs.redislabs.com/latest/rs/security/ldap/'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54662r804869_chk'
  tag severity: 'medium'
  tag gid: 'V-251227'
  tag rid: 'SV-251227r804871_rule'
  tag stig_id: 'RD6X-00-009300'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag fix_id: 'F-54616r804870_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
