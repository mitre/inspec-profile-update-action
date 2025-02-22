control 'SV-53914' do
  title 'SQL Server must maintain and support organization-defined security labels on information in process.'
  desc 'Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the application and are used to enable the implementation of access control and flow control policies; reflect special dissemination, handling, or distribution instructions; or support other aspects of the information security policy.

Organizations define the security attributes of their data (e.g., classified, FOUO). Applications generating and/or processing data assigned these organization-defined security attributes must maintain the binding of these attributes to the data when the data is transmitted.

If the application does not maintain the data security attributes when it transmits the data, there is a risk of data compromise.

The sensitivity marking or labeling of data items promotes the correct handling and protection of data. Without such notification, the user may unwittingly disclose sensitive data to unauthorized users. Security labels must be correctly maintained throughout transmission.

(Earlier releases of this STIG suggested using the SQL Server Label Security Toolkit, from codeplex.com.  However, codeplex.com has been shut down, and it is unclear whether the Toolkit is still supported.  If the organization does have access to the Toolkit, it may still be used, provided the organization accepts responsibility for its support.)'
  desc 'check', 'Review system documentation to determine if the labeling of sensitive data is required under organization-defined guidelines.

If the labeling of sensitive data is not required, this is NA.

Obtain system configuration settings to determine how data labeling is being performed. This can be through triggers or some other SQL-developed means or via a third-party tool.  

If the labeling of sensitive information in process is not being performed, this is a finding.'
  desc 'fix', 'Develop SQL or application code or acquire a third party tool to perform data labeling.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47926r3_chk'
  tag severity: 'medium'
  tag gid: 'V-41391'
  tag rid: 'SV-53914r4_rule'
  tag stig_id: 'SQL2-00-000400'
  tag gtitle: 'SRG-APP-000007-DB-000184'
  tag fix_id: 'F-46814r6_fix'
  tag 'documentable'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
end
