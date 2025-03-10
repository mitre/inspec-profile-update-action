control 'SV-53917' do
  title 'SQL Server must allow authorized users to associate security labels to information in the database.'
  desc 'Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the information system and are used to enable the implementation of access control and flow control policies; reflect special dissemination, handling, or distribution instructions, or support other aspects of the information security policy.

Examples of application security attributes are classified, FOUO, sensitive, etc.

Throughout the course of normal usage, authorized users of applications that handle sensitive data will have the need to associate security attributes with information. Applications that maintain the binding of organization-defined security attributes to data must ensure authorized users can associate security attributes with information. For databases, this is accomplished via labeling.'
  desc 'check', 'Review system documentation to determine if the labeling of sensitive data is required under organization-defined guidelines.
If the labeling of sensitive data is not required, this is NA.

Obtain system configuration setting to determine how data labeling is being performed. This can be through triggers or some other SQL-developed means or via a third-party tool. Determine how authorized users associate security information to data. If authorized users are not able to associate security labels to data, this is a finding.'
  desc 'fix', 'Develop SQL code or acquire a third party tool to perform data labeling. SQL Server Label Security Toolkit can be downloaded from http://www.codeplex.com. This tool can satisfy all data labeling and security data labeling requirements.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47929r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41393'
  tag rid: 'SV-53917r3_rule'
  tag stig_id: 'SQL2-00-000900'
  tag gtitle: 'SRG-APP-000012-DB-000192'
  tag fix_id: 'F-46817r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002289']
  tag nist: ['AC-16 (4)']
end
