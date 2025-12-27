control 'SV-206570' do
  title 'The DBMS must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', 'If the application owner and Authorizing Official have determined that encryption of data at rest is NOT required, this is not a finding.

Review DBMS settings to determine whether controls exist to protect the confidentiality and integrity of data at rest in the database.

If controls do not exist or are not enabled, this is a finding.'
  desc 'fix', 'Apply appropriate controls to protect the confidentiality and integrity of data at rest in the database.'
  impact 0.7
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6830r291378_chk'
  tag severity: 'high'
  tag gid: 'V-206570'
  tag rid: 'SV-206570r810841_rule'
  tag stig_id: 'SRG-APP-000231-DB-000154'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-6830r291379_fix'
  tag 'documentable'
  tag legacy: ['SV-42871', 'V-32534']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
