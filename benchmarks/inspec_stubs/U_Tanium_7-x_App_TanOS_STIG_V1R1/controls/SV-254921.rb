control 'SV-254921' do
  title 'The Tanium application must reveal error messages only to the ISSO, ISSM, and SA.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the application. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Enter "C" for "User Administration Menu," and then press "Enter".

4. Enter "U" for "TanOS User Management," and then press "Enter".

If there are any users other than the documented approved TanOS users this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role, or any additional user with administrative privileges.

3. Enter "C" for "User Administration Menu," and then press "Enter".

4. Enter "U" for "TanOS User Management," and then press "Enter".

5. Work with Tanium System Administrator to either document approved accounts or remove nonapproved accounts.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58534r867661_chk'
  tag severity: 'medium'
  tag gid: 'V-254921'
  tag rid: 'SV-254921r867663_rule'
  tag stig_id: 'TANS-AP-000655'
  tag gtitle: 'SRG-APP-000267'
  tag fix_id: 'F-58478r867662_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
