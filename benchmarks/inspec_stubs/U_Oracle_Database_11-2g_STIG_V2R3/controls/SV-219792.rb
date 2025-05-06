control 'SV-219792' do
  title 'The DBMS software installation account must be restricted to authorized users.'
  desc 'When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 

If the application were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement is contingent upon the language in which the application is programmed, as many application architectures in use today incorporate their software libraries into, and make them inseparable from, their compiled distributions, rendering them static and version-dependent. However, this requirement does apply to applications with software libraries accessible and configurable, as in the case of interpreted languages.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

DBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a greater impact on database security and operation. It is especially important to grant access to privileged accounts to only those persons who are qualified and authorized to use them.'
  desc 'check', 'Review procedures for controlling and granting access to use of the DBMS software installation account. If access or use of this account is not restricted to the minimum number of personnel required, or if unauthorized access to the account has been granted, this is a finding.'
  desc 'fix', 'Develop, document, and implement procedures to restrict use of the DBMS software installation account.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21517r307225_chk'
  tag severity: 'medium'
  tag gid: 'V-219792'
  tag rid: 'SV-219792r395850_rule'
  tag stig_id: 'O112-P2-010800'
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag fix_id: 'F-21516r307226_fix'
  tag 'documentable'
  tag legacy: ['SV-66653', 'V-52437']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
