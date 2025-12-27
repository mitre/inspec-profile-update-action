control 'SV-253721' do
  title 'MariaDB must associate organization-defined types of security labels having organization-defined security label values with information in transmission.'
  desc 'Without the association of security labels to information, there is no basis for MariaDB to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. 

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. 

One example includes marking data as classified or CUI. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling in MariaDB is custom application code.'
  desc 'check', 'If security labeling is not required, this is not a finding.

If security labeling requirements have been specified, but the security labeling is not implemented or does not reliably maintain labels on information in transmission, this is a finding.'
  desc 'fix', 'Add custom data structures, data elements and application code, to provide reliable security labeling of information in transmission. Write Custom Code: https://mariadb.com/resources/blog/protect-your-data-row-level-security-in-mariadb-10-0/'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57173r841686_chk'
  tag severity: 'medium'
  tag gid: 'V-253721'
  tag rid: 'SV-253721r841688_rule'
  tag stig_id: 'MADB-10-006600'
  tag gtitle: 'SRG-APP-000314-DB-000310'
  tag fix_id: 'F-57124r841687_fix'
  tag 'documentable'
  tag cci: ['CCI-002264']
  tag nist: ['AC-16 a']
end
