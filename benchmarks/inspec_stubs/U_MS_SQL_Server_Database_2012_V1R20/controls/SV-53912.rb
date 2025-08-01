control 'SV-53912' do
  title 'SQL Server must maintain and support organization-defined security labels on stored information.'
  desc 'Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the information system and are used to enable the implementation of access control and flow control policies; reflect special dissemination, handling, or distribution instructions; or support other aspects of the information security policy.

One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing but, either way, it is imperative these assignments are maintained while the data is in storage. If the security attributes are lost when the data is stored, there is the risk of a data compromise.

The sensitivity marking or labeling of stored data items promotes the correct handling and protection of data.  Without such notification, the user may unwittingly disclose sensitive data to unauthorized users.

(Earlier releases of this STIG suggested using the SQL Server Label Security Toolkit, from codeplex.com.  However, codeplex.com has been shut down, and it is unclear whether the Toolkit is still supported.  If the organization does have access to the Toolkit, it may still be used, provided the organization accepts responsibility for its support.)'
  desc 'check', 'Review system documentation to determine if the labeling of sensitive data is required under organization-defined guidelines.
If the labeling of sensitive data is not required, this is NA.

Obtain system configuration settings to determine how data labeling is being performed. This can be through triggers or some other SQL-developed means or via a third-party tool. Spot check data and ensure the appropriate labels have been applied to stored data.   

If the labeling of sensitive data is required and is not being performed, this is a finding.'
  desc 'fix', 'Develop SQL or application code or acquire a third party tool to perform data labeling.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47925r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41389'
  tag rid: 'SV-53912r4_rule'
  tag stig_id: 'SQL2-00-000300'
  tag gtitle: 'SRG-APP-000006-DB-000183'
  tag fix_id: 'F-46813r5_fix'
  tag 'documentable'
  tag cci: ['CCI-002262']
  tag nist: ['AC-16 a']
end
