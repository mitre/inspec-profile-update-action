control 'SV-24449' do
  title 'The database should not be directly accessible from public or unauthorized networks.'
  desc 'Databases often store critical and/or sensitive information used by the organization. For this reason, databases are targeted for attacks by malicious users. Additional protections provided by network defenses that limit accessibility help protect the database and its data from unnecessary exposure and risk.'
  desc 'check', 'Review the System Security Plan to determine if the DBMS serves data to users or applications outside the local enclave.

If the DBMS is not accessed outside of the local enclave, this check is Not a Finding.

If the DBMS serves applications available from a public network (e.g. the Internet), then confirm that the application servers are located in a DMZ.

If the DBMS is located inside the local enclave and is directly accessible to public users, this is a Finding.

If the DBMS serves public-facing applications and is not protected from direct client connections and unauthorized networks, this is a Finding.

If the DBMS serves public-facing applications and contains sensitive or classified information, this is a Finding.'
  desc 'fix', 'Do not allow direct connections from users originating from the Internet or other public network to the DBMS.

Include in the System Security Plan for the system whether the DBMS serves public-facing applications or applications serving users from other untrusted networks.

Do not store sensitive or classified data on a DBMS server that serves public-facing applications.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29392r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15122'
  tag rid: 'SV-24449r1_rule'
  tag stig_id: 'DG0186-ORACLE11'
  tag gtitle: 'DBMS network perimeter protection'
  tag fix_id: 'F-26418r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
