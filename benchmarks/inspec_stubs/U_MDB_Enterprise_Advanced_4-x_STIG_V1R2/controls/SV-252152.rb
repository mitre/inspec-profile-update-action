control 'SV-252152' do
  title 'MongoDB software installation account must be restricted to authorized users.'
  desc 'When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can have significant effects on the overall security of the system.

If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed access to information system components for purposes of initiating changes, including upgrades and modifications.

DBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a great impact on database security and operation. It is especially important to grant privileged access to only those persons who are qualified and authorized to use them.'
  desc 'check', 'Review procedures for controlling, granting access to, and tracking use of the DBMS software installation account.

If access or use of this account is not restricted to the minimum number of personnel required or if unauthorized access to the account has been granted, this is a finding.'
  desc 'fix', 'Develop, document, and implement procedures to restrict and track use of the DBMS software installation account.'
  impact 0.7
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55608r813836_chk'
  tag severity: 'high'
  tag gid: 'V-252152'
  tag rid: 'SV-252152r863320_rule'
  tag stig_id: 'MD4X-00-002100'
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag fix_id: 'F-55558r813837_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
