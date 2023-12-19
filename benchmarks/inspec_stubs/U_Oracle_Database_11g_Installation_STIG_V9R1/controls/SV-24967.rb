control 'SV-24967' do
  title 'Passwords should be encrypted when transmitted across the network.'
  desc 'DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.'
  desc 'check', 'Oracle natively encrypts passwords in transit when using Oracle connection protocols and products (i.e. Oracle Client).

Where other connection products and protocols are used, review configuration options for encrypting passwords during login events across the network.

If passwords are not encrypted, this is a Finding.

Where only Oracle connection protocols and products are used and password encryption is not purposely disabled and enabled where applicable, this is Not a Finding.

If determined that passwords are passed unencrypted at any point along the transmission path between the source and destination, this is a Finding.'
  desc 'fix', 'Utilize Oracle connection protocols and products (i.e. Oracle Client) where possible.

Where other connection products and protocols are used, ensure configuration options for encrypting passwords during login events across the network are used.

If the database does not provide encryption for login events natively, employ encryption at the OS or network level.

Ensure passwords remain encrypted from source to destination.'
  impact 0.7
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29867r1_chk'
  tag severity: 'high'
  tag gid: 'V-15636'
  tag rid: 'SV-24967r1_rule'
  tag stig_id: 'DG0129-ORACLE11'
  tag gtitle: 'DBMS passwords in transit'
  tag fix_id: 'F-25688r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
