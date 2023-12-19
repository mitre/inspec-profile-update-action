control 'SV-215173' do
  title 'If the AIX system is using LDAP for authentication or account information, the LDAP SSL, or TLS connection must require the server provide a certificate and this certificate must have a valid path to a trusted CA.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.'
  desc 'check', %q(If LDAP authentication is not used on AIX, this is Not Applicable.

Note: Depending on which version of GSKit is installed on AIX, the GSK commands that are used to manage the Key Database (KDB) have different names. The possible GSK commands are: gsk8capicmd (used below), gsk8capicmd_64 and gsk7cmd.

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

Identify the Key Database (KDB), and its password, by asking the ISSO/SA. If no Key Database exists on the system, this is a finding.

List the certificate issuer with GSK command:

# gsk8capicmd -cert -list CA -db <KDB_FILE> -pw <KDB_PASSWORD> 

Make note of the client Key Label: 

# gsk8capicmd -cert -details -showOID -db <KDB_FILE> -pw <KDB_PASSWORD> -label <Key Label> 

If the certificate is not issued by DoD PKI or a DoD-approved external PKI, this is a finding

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
  tag check_id: 'C-16371r293970_chk'
  tag severity: 'medium'
  tag gid: 'V-215173'
  tag rid: 'SV-215173r508663_rule'
  tag stig_id: 'AIX7-00-001006'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-16369r293971_fix'
  tag 'documentable'
  tag legacy: ['V-91277', 'SV-101375']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
