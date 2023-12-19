control 'SV-206557' do
  title 'If passwords are used for authentication, the DBMS must transmit only encrypted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.'
  desc 'check', 'Review configuration settings for encrypting passwords in transit across the network. If passwords are not encrypted, this is a finding. 

If it is determined that passwords are passed unencrypted at any point along the transmission path between the source and destination, this is a finding.'
  desc 'fix', 'Configure encryption for transmission of passwords across the network. If the database does not provide encryption for logon events natively, employ encryption at the OS or network level.

Ensure passwords remain encrypted from source to destination.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6817r291339_chk'
  tag severity: 'medium'
  tag gid: 'V-206557'
  tag rid: 'SV-206557r617447_rule'
  tag stig_id: 'SRG-APP-000172-DB-000075'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-6817r291340_fix'
  tag 'documentable'
  tag legacy: ['SV-42806', 'V-32469']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
