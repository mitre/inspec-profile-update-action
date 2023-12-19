control 'SV-23715' do
  title 'Regular documented testing of hardware based COOP/backup or emergency telephones is not performed in accordance with a documented test plan or related documentation is deficient or non existent.'
  desc 'Backup/COOP or emergency telephones are useless if they don’t work. Thus they need to be tested regularly to ensure their functionality, particularly if they are not used regularly. Regular use will detect non functionality issues quickly. If not regularly used, service can be disrupted and the phone rendered inoperable without detection until a situation arose requiring its use. There’s nothing worse than a non functional communications device in an emergency situation. 

As such, a regular testing plan for backup/COOP or emergency telephones must be developed and documented that includes a record of the tests performed. The records of the test should include such information as the instrument being tested, date and potentially the time the test was performed, the name of the person performing the test, and whether the phone is functional or not. Additional information should be added if the phone is found to be non-functional such as maintenance actions taken and when service was restored.

 The frequency of testing for each instrument is variable but should minimally be monthly. Weekly, daily, or randomly within a monthly cycle is better.  Testing may be made the responsibility of the user(s) the instrument serves providing they document their tests.

Testing should include the placement of a call. While testing for the presence of dial tone could be a minimal test, this may not be an accurate indicator that a call can be completed.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

In the event hardware based instruments are implemented in a COOP capacity for backup or emergency communications, and such instruments are not regularly used, the IAO will ensure the functionality of these instruments by implementing and documenting a testing program which will include the documentation of the results of each test. 

NOTE: The frequency of testing for each instrument is variable but should minimally be monthly. Weekly, daily, or randomly within a monthly cycle is better.  Testing may be made the responsibility of the user(s) the instrument serves providing they document their tests. The test could minimally involve determining if dial tone is present (unless generated within the phone as with some VoIP phones), but should include the placement of a call to an emergency number.'
  desc 'fix', 'In the event hardware based instruments are implemented in a COOP capacity for backup or emergency communications, and such instruments are not regularly used, the IAO will ensure the functionality of these instruments by implementing and documenting a testing program which will include the documentation of the results of each test. 

NOTE: The frequency of testing for each instrument is variable but should minimally be monthly. Weekly, daily, or randomly within a monthly cycle is better.  Testing may be made the responsibility of the user(s) the instrument serves providing they document their tests. The test could minimally involve determining if dial tone is present (unless generated within the phone as with some VoIP phones), but should include the placement of a call to an emergency number.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-25737r1_chk'
  tag severity: 'low'
  tag gid: 'V-21506'
  tag rid: 'SV-23715r1_rule'
  tag stig_id: 'VVoIP 1921 (GENERAL)'
  tag gtitle: 'Deficient testing: COOP/Emergency phones'
  tag fix_id: 'F-22295r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'The inability to make an emergency or any call in the event the COOP/backup/emergency telephone is nonfunctional.'
  tag responsibility: ['Security Manager', 'Information Assurance Manager', 'Information Assurance Officer']
end
