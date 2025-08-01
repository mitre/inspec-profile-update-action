control 'SV-93573' do
  title 'The IBM z/VM TCP/IP Key database for LDAP or SSL server must be created with the proper permissions.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'Issue command openvm list /etc./gskadm/ (own)

If the file permissions are as displayed below, this is not a finding.

User ID Group Name Permissions Type Path name component

gskadmin security rw- r-- --- F ’Database.kdb’

gskadmin security rw- --- --- F ’Database.rdb’

gskadmin security rw- r-- --- F ’Database.sth’'
  desc 'fix', 'Ensure proper permissions are assigned to Key databases.

Issue the “OPENVM PERMIT” commands to assign proper permissions.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78453r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78867'
  tag rid: 'SV-93573r1_rule'
  tag stig_id: 'IBMZ-VM-000470'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-85617r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
