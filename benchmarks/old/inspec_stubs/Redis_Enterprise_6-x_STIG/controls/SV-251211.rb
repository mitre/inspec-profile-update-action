control 'SV-251211' do
  title 'Redis Enterprise DBMS software installation account must be restricted to authorized users.'
  desc 'When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can have significant effects on the overall security of the system. 

If the system were to allow any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed access to information system components for purposes of initiating changes, including upgrades and modifications.

DBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a great impact on database security and operation. It is especially important to grant privileged access to only those persons who are qualified and authorized to use them.'
  desc 'check', 'To install the software, the user must have root level access to each node it will be installed on. Review the procedure used to install Redis Enterprise. In this procedure, users are capable of selecting their own user to own the software. Typically, this is run under a Redis Labs system user.

To check this requirement, investigate the user used and verify that only the appropriate people are able to access this account on the host operating system. 

If more than the appropriate people can access this account, this is a finding.'
  desc 'fix', 'User must have root level access to the system prior to installing Redis Enterprise. Without this, the installation will not complete, and no changes will be made. Review the procedure used to install Redis Enterprise. In this procedure, users are capable of selecting their own user to own the software. Typically, this is run under a Redis Labs system user.

To check this requirement, investigate the user used and ensure that only the appropriate people are able to access this account on the host operating system.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54646r804821_chk'
  tag severity: 'medium'
  tag gid: 'V-251211'
  tag rid: 'SV-251211r804823_rule'
  tag stig_id: 'RD6X-00-007400'
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag fix_id: 'F-54600r804822_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
