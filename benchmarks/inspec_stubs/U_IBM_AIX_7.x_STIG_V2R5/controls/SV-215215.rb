control 'SV-215215' do
  title 'AIX must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI-certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.'
  desc 'check', %q(Note: Depending on which version of GSKit is installed on AIX, the GSK commands that are used to manage the Key Database (KDB) have different names. The possible GSK commands are: gsk8capicmd (used below), gsk8capicmd_64 and gsk7cmd.

Check if the system is using LDAP authentication: 

# grep LDAP /etc/security/user 

If no lines are returned, this requirement is not applicable. 

Check if the useSSL option is enabled: 

# grep '^useSSL' /etc/security/ldap/ldap.cfg 
useSSL:yes

If "yes" is not the returned value, this is a finding. 

Verify a certificate is used for client authentication to the server: 

# grep -i '^ldapsslkeyf' /etc/security/ldap/ldap.cfg 
ldapsslkeyf:/tmp/key.kdb

If no line is found, this is a finding. 

Identify the Key Database (KDB), and its password, by asking the ISSO/SA). 

If  no Key Database exists on the system, this is a finding.

List the certificate issuer with IBM GSK:

# gsk8capicmd -cert -list CA -db <KDB_FILE> -pw <KDB_PASSWORD> 

Make note of the client Key Label: 

# gsk8capicmd -cert -details -showOID -db <KDB_FILE> -pw <KDB_PASSWORD> -label <Key Label> 

If the certificate is not issued by DoD PKI or a DoD-approved external PKI, this is a finding.

The IBM GSK Database should only have certificates for the client system and for the LDAP server. 

If more certificates are in the key database than the LDAP server and the client, this is a finding.)
  desc 'fix', 'Note: Depending on which version of GSKit is installed on AIX, the GSK commands that are used to manage the Key Database (KDB) have different names. The possible GSK commands are: gsk8capicmd (used below), gsk8capicmd_64 and gsk7cmd.

Create a key database with DoD PKI or DoD-approved certificate using one of the following commands: 
# gsk8capicmd -keydb -create -db <KDB_FILE> -pw <KDB_PASSWORD> -type cms -stash

Edit "/etc/security/ldap/ldap.cfg" and add or edit the "ldapsslkeyf" setting to reference a KDB file containing a client certificate issued by DoD PKI or a DoD-approved external PKI. 

Install a certificate signed by a DoD PKI or a DoD-approved external PKI using the following command: 
# gsk8capicmd -cert -add -db <KDB_FILE> -pw <KDB_PASSWORD> -file <CERT_FILE> -label <CERT_LABEL>

Remove un-needed CA certificates using one of the following commands: 
# gsk8capicmd -cert -delete -db <KDB_FILE> -pw <KDB_PASSWORD> -label <CERT_LABEL>

Restart LDAP client using command:
# /usr/sbin/restart-secldapclntd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16413r294096_chk'
  tag severity: 'medium'
  tag gid: 'V-215215'
  tag rid: 'SV-215215r508663_rule'
  tag stig_id: 'AIX7-00-001105'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-16411r294097_fix'
  tag 'documentable'
  tag legacy: ['SV-101655', 'V-91557']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
