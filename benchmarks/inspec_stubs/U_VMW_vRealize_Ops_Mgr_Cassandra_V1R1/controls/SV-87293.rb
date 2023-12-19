control 'SV-87293' do
  title 'The Cassandra database log configuration file must set internode encryption.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.'
  desc 'check', "Review configuration settings for encrypting passwords in transit across the network. If passwords are not encrypted, this is a finding. 

At the command prompt, execute the following command:

# grep '^\\s*internode_encryption:' /usr/lib/vmware-vcops/user/conf/cassandra/cassandra.yaml

If the line below is returned, this is a finding:
internode_encryption: all"
  desc 'fix', "Configure encryption for transmission of passwords across the network. If the database does not provide encryption for logon events natively, employ encryption at the OS or network level.

At the command line execute the following command:

# sed -i 's/^.*\\binternode_encryption:.*$/internode_encryption: all/' /usr/lib/vmware-vcops/user/conf/cassandra/cassandra.yaml"
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72661'
  tag rid: 'SV-87293r1_rule'
  tag stig_id: 'VROM-CS-000140'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-79065r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
