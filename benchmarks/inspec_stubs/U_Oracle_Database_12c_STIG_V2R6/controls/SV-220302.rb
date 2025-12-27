control 'SV-220302' do
  title 'The DBMS must restrict error messages so only authorized personnel may view them.'
  desc 'If the application provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

Some default DBMS error messages can contain information that could aid an attacker in, among others things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information. It is important that error messages are displayed only to those who are authorized to view them.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', "Check DBMS settings and custom database code to determine if error messages are ever displayed to unauthorized individuals: 

i)  Review all end-user-facing applications that use the database, to determine whether they display any DBMS-generated error messages to general users.  If they do, this is a finding.

ii) Review whether the database is accessible to users who are not authorized system administrators or database administrators, via the following types of software:
iia) Oracle SQL*Plus
iib) Reporting and analysis tools
iic) Database management and/or development tools, such as, but not limited to, Toad.
iid) Application development tools, such as, but not limited to, Oracle JDeveloper, Microsoft Visual Studio, PowerBuilder, or Eclipse.

If the answer to the preceding question (iia through iid) is Yes, inquire whether, for each role or individual with respect to each tool, this access is required to enable the user(s) to perform authorized job duties.  If No, this is a finding. If Yes, continue:

For each tool in use, determine whether it is capable of suppressing DBMS-generated error messages, and if it is, whether it is configured to do so.

Determine whether the role or individual, with respect to each tool, needs to see detailed DBMS-generated error messages.

If No, and if the tool is not configured to suppress such messages, this is a finding.

If Yes, determine whether the role/user's need to see such messages is documented in the System Security Plan.  If so, this is not a finding. If not, this is a finding."
  desc 'fix', 'i)  For each end-user-facing application that displays DBMS-generated error messages, configure or recode it to suppress these messages.

If the application is coded in Oracle PL/SQL, the EXCEPTION block can be used to suppress or divert error messages.  Most other programming languages provide comparable facilities, such as TRY ... CATCH.

ii) For each unauthorized user of each tool, remove the ability to access it.  For each tool where access to DBMS error messages is not required and can be configured, suppress the messages.  For each role/user that needs access to the error messages, or needs a tool where the messages cannot be suppressed, document the need in the system security plan.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22017r392037_chk'
  tag severity: 'medium'
  tag gid: 'V-220302'
  tag rid: 'SV-220302r397846_rule'
  tag stig_id: 'O121-C2-020000'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-22009r392038_fix'
  tag 'documentable'
  tag legacy: ['SV-76283', 'V-61793']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
