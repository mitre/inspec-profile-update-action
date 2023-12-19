control 'SV-215174' do
  title 'If AIX is using LDAP for authentication or account information, the /etc/ldap.conf file (or equivalent) must not contain passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', %q(Examine the LDAP configuration file "/etc/security/ldap/ldap.cfg" for possible clear-text password for "bindpwd".

From the command prompt, run the following command:
# grep ^bindpwd: /etc/security/ldap/ldap.cfg

The above command should yield the following output:
bindpwd:{DESv2}57AEE2BCED 764373462FC7B62736D9A

If the returned entry has an unencrypted password (the output line does not start with "bindpwd:{DES"), this is a finding. 

Examine the LDAP configuration file "/etc/security/ldap/ldap.cfg" for using stashed password for SSL key database (KDB).

Check for "ldapsslkeypwd" in LDAP config file using the follow command: 
# grep '^ldapsslkeypwd' /etc/security/ldap/ldap.cfg 

If the command returned a line, this is a finding.)
  desc 'fix', 'To remove the clear-text password for "bindpwd", do the following two steps:
Edit "/etc/security/ldap/ldap.cfg" to remove the "bindpwd" line and save the change; 

Re-config the LDAP client using the "mksecldap" command:
# mksecldap -c -h <LDAP_HOST:LDAP_PORT> -A <auth_type> -D <Default_Entry> -d <BASE_DN> -a <BIND_USER> -p <BIND_PASSWORD> -k <KDB_FILE> -w <KDB_PASSWORD>

Note: Depending on which version of GSKit is installed on AIX, the GSK commands that are used to manage the Key Database (KDB) have different names. The possible GSK commands are: "gsk8capicmd" (used below), "gsk8capicmd_64" and "gsk7cmd".

To use the stashed password for SSL key database (KDB), do the following two steps:
Edit "/etc/security/ldap/ldap.cfg" to remove the "ldapsslkeypwd" line and save the change;

Run the "gsk8capicmd" to create a stashed password file for the SSL KDB:
# gsk8capicmd -keydb -stashpw -db <KDB_FILE> -pw <KDB_PASSWORD>'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16372r293973_chk'
  tag severity: 'high'
  tag gid: 'V-215174'
  tag rid: 'SV-215174r508663_rule'
  tag stig_id: 'AIX7-00-001007'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-16370r293974_fix'
  tag 'documentable'
  tag legacy: ['V-91291', 'SV-101389']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
