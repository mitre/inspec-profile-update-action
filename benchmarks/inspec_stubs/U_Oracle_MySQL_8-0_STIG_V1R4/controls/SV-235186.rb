control 'SV-235186' do
  title 'The MySQL Database Server 8.0 must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When transmitting data, the DBMS, associated applications, and infrastructure must leverage transmission protection mechanisms.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

Run the following:
select @@require_secure_transport;

The value should be 1 (ON) versus 0 (OFF), if the value is 0 (OFF), this is a finding.'
  desc 'fix', 'Turn on require_secure_transport. In this mode the server permits only TCP/IP connections encrypted using TLS/SSL, or connections that use a socket file (on UNIX) or shared memory (on Windows). 

The server rejects nonsecure connection attempts, which fail with an ER_SECURE_TRANSPORT_REQUIRED error.

set persist require_secure_transport=ON;'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38405r623678_chk'
  tag severity: 'medium'
  tag gid: 'V-235186'
  tag rid: 'SV-235186r879812_rule'
  tag stig_id: 'MYS8-00-011300'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-38368r623679_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
