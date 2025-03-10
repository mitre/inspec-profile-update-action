control 'SV-220308' do
  title 'The DBMS software installation account must be restricted to authorized users.'
  desc 'When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

If the application were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement is contingent upon the language in which the application is programmed, as many application architectures in use today incorporate their software libraries into, and make them inseparable from, their compiled distributions, rendering them static and version-dependent. However, this requirement does apply to applications with software libraries accessible and configurable, as in the case of interpreted languages.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

DBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a greater impact on database security and operation. It is especially important to grant access to privileged accounts to only those persons who are qualified and authorized to use them.

This requirement is particularly important because Oracle equates the installation account with the SYS account - the super-DBA.  Once logged on to the operating system, this account can connect to the database AS SYSDBA without further authentication.  It is very powerful and, by virtue of not being linked to any one person, cannot be audited to the level of the individual.'
  desc 'check', 'Review procedures for controlling and granting access to use of the DBMS software installation account.

If access or use of this account is not restricted to the minimum number of personnel required, or if unauthorized access to the account has been granted, this is a finding.'
  desc 'fix', 'Develop, document, and implement procedures to restrict use of the DBMS software installation account.'
  impact 0.7
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22023r392055_chk'
  tag severity: 'high'
  tag gid: 'V-220308'
  tag rid: 'SV-220308r879586_rule'
  tag stig_id: 'O121-P2-010800'
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag fix_id: 'F-22015r392056_fix'
  tag 'documentable'
  tag legacy: ['SV-76363', 'V-61873']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
