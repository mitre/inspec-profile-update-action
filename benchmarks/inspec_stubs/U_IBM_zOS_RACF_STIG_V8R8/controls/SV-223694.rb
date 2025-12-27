control 'SV-223694' do
  title 'IBM RACF OPERAUDIT SETROPTS value must set to OPERAUDIT.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts List

If the OPERAUDIT value is listed as one of the ATTRIBUTES, this is not a finding.

If the OPERAUDIT value is not listed as one of the ATTRIBUTES, this is a finding.'
  desc 'fix', 'NOTE: The RACF AUDITOR attribute is required in order to specify SETROPTS OPERAUDIT and also to display the OPERAUDIT attribute with the SETROPTS LIST command.

Configure the OPERAUDIT SETROPTS value to be set to OPERAUDIT. This specifies that RACF logs all actions such as accesses to resources and commands for a user who has operations or group operations attribute.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including a list of ATTRIBUTES. 

Logging of all actions, such as accesses to resources and commands, allowed only because a user has the OPERATIONS or group-OPERATIONS attribute is activated with the command SETR OPERAUDIT.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25367r514770_chk'
  tag severity: 'medium'
  tag gid: 'V-223694'
  tag rid: 'SV-223694r853600_rule'
  tag stig_id: 'RACF-ES-000470'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-25355r514771_fix'
  tag 'documentable'
  tag legacy: ['SV-107199', 'V-98095']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
