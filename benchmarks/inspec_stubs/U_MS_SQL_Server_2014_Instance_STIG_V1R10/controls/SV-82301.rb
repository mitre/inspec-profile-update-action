control 'SV-82301' do
  title 'SQL Server software installation account(s) must be restricted to authorized users.'
  desc 'When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

If the application were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement is contingent upon the language in which the application is programmed, as many application architectures in use today incorporate their software libraries into, and make them inseparable from, their compiled distributions, rendering them static and version dependent. However, this requirement does apply to applications with software libraries accessible and configurable, as in the case of interpreted languages.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

DBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a greater impact on SQL Server security and operation. It is especially important to grant access to privileged accounts to only those persons who are qualified and authorized to use them.'
  desc 'check', 'Check system documentation for policy and procedures to restrict use of the SQL Server software installation account.

Check OS settings to determine whether users are restricted from accessing SQL Server objects and data they are not authorized to access by checking the local OS user accounts.

From a Command Prompt, open lusrmgr.msc. Navigate to Users >> right-click individual user >> Properties >> Member Of.

If appropriate access controls for all users are not implemented to restrict access to only authorized users and to restrict the access of those users to objects and data they are authorized, this is a finding.

Review procedures for controlling and granting access to use of the SQL Server software installation account.

If access or use of this account is not restricted to the minimum number of personnel required, or unauthorized access to this account has been granted, this is a finding.'
  desc 'fix', 'From a Command Prompt, open lusrmgr.msc.  Navigate to Users >> right-click individual user >> Properties >> Member Of.

Configure SQL Server & OS settings and access controls, to restrict user access to objects and data that the user is authorized to view or interact with.

Develop, document, and implement procedures to restrict use of the DBMS software installation account.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68379r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67811'
  tag rid: 'SV-82301r1_rule'
  tag stig_id: 'SQL4-00-015400'
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag fix_id: 'F-73927r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
