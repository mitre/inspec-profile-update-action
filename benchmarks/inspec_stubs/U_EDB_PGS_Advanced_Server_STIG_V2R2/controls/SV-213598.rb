control 'SV-213598' do
  title 'If passwords are used for authentication, the EDB Postgres Advanced Server must transmit only encrypted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.'
  desc 'check', 'Open "<postgresql data directory>/pg_hba.conf" in a viewer or editor.  (The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)

If any rows have "password" specified for the "METHOD" column, this is a finding.'
  desc 'fix', 'Open "<postgresql data directory>/pg_hba.conf" in an editor.  (The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)

For any rows that have "password" specified for the "METHOD" column, change the value to "md5".'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14820r290106_chk'
  tag severity: 'high'
  tag gid: 'V-213598'
  tag rid: 'SV-213598r836840_rule'
  tag stig_id: 'PPS9-00-004400'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-14818r290107_fix'
  tag 'documentable'
  tag legacy: ['SV-83553', 'V-68949']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
