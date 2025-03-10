control 'SV-235184' do
  title 'The MySQL Database Server 8.0 must associate organization-defined types of security labels having organization-defined security label values with information in transmission.'
  desc 'Without the association of security labels to information, there is no basis for the DBMS to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. 

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. 

One example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of the DBMS product, a third-party product, or custom application code.

For MySQL, a view or stored procedures can limit access to only selected columns of the base table. A view can provide value-based security for the information in a table. To use a view requires appropriate privileges only for the view itself. The user need not be given privileges on base objects underlying the view.'
  desc 'check', 'If security labeling is not required, this is not a finding.

If security labeling requirements have been specified, check for a MySQL solution using views and Stored Procedures to implement a row-level security solution that reliably maintains labels on information in storage. 

For data that have been labeled with a column indicating data is classified read-only, views can be created and secured via access privileges such that a user can only view the data that have a specific tag or tags (e.g., user [x] can only view records that are labeled with the tag of classified). 

If a MySQL solution through the use of views and stored procedures or a third party solution does not exist, this is a finding.'
  desc 'fix', 'Deploy MySQL Views and Stored Procedures or a third-party software, or add custom data structures, data elements and application code, to provide reliable security labeling of information in storage.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38403r623672_chk'
  tag severity: 'medium'
  tag gid: 'V-235184'
  tag rid: 'SV-235184r855582_rule'
  tag stig_id: 'MYS8-00-011000'
  tag gtitle: 'SRG-APP-000314-DB-000310'
  tag fix_id: 'F-38366r623673_fix'
  tag 'documentable'
  tag cci: ['CCI-002264']
  tag nist: ['AC-16 a']
end
