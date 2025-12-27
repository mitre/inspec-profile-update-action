control 'SV-87319' do
  title 'The Cassandra Server must implement cryptographic mechanisms preventing the unauthorized disclosure of information at rest.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the DBMS or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', 'Review the Cassandra Server to ensure cryptographic mechanisms are implemented preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.
 
Inspect the server configuration to ensure a full disk encryption solution has been implemented. If the disk is unencrypted, this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to implement cryptographic mechanisms preventing the unauthorized disclosure of information at rest.

Implement full disk encryption such as VMcrypt or other third-party full disk encryption that uses FIPS 140-2 validated cryptography.'
  impact 0.7
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72843r1_chk'
  tag severity: 'high'
  tag gid: 'V-72687'
  tag rid: 'SV-87319r1_rule'
  tag stig_id: 'VROM-CS-002125'
  tag gtitle: 'SRG-APP-000429-DB-000387'
  tag fix_id: 'F-79091r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
