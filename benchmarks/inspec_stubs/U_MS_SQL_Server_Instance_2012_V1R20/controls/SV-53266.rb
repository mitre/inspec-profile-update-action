control 'SV-53266' do
  title 'SQL Server must associate and maintain security labels when exchanging information between systems.'
  desc 'When data is exchanged between information systems, the security attributes associated with said data need to be maintained.  

Security attributes are an abstraction representing the basic properties or characteristics of an entity with respect to safeguarding information, typically associated with internal data structures (e.g., records, buffers, files) within the information system and used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. 

Security attributes may be explicitly or implicitly associated with the information contained within the information system. 

If database security labels are not maintained as information moves between systems, handling instructions can be lost and data can be accidentally distributed to unauthorized individuals.'
  desc 'check', 'Review system documentation to determine if the labeling of sensitive data is required under organization-defined guidelines.

If the labeling of sensitive data is not required, this is NA.

Obtain system configuration setting to determine how data labeling is being performed. This can be through triggers or some other SQL developed means or via a third-party tool. Check to ensure that labels are being associated to data when information is being exchanged between systems.   

If the labeling is not being associated to data when exchanging data between systems, this is a finding.'
  desc 'fix', 'Develop SQL code or acquire a third party tool to perform data labeling. SQL Server Label Security Toolkit can be downloaded from http://www.codeplex.com. This tool can satisfy all data labeling and security data labeling requirements.'
  impact 0.3
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47567r2_chk'
  tag severity: 'low'
  tag gid: 'V-40912'
  tag rid: 'SV-53266r3_rule'
  tag stig_id: 'SQL2-00-020400'
  tag gtitle: 'SRG-APP-000203-DB-000146'
  tag fix_id: 'F-46194r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001157']
  tag nist: ['SC-16']
end
