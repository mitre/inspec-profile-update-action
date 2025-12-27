control 'SV-223700' do
  title 'The IBM RACF REALDSN SETROPTS value must be specified.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts list

If the REALDSN is enabled then the message "REAL DATA SET NAMES OPTION IS ACTIVE" will be displayed, this is not a finding.

If the message "REAL DATA SET NAMES OPTION IS INACTIVE" is displayed, this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Configure control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including the value for the REALDSN Option. 

REALDSN is ACTIVATED by issuing the command SETR REALDSN.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25373r514788_chk'
  tag severity: 'medium'
  tag gid: 'V-223700'
  tag rid: 'SV-223700r604139_rule'
  tag stig_id: 'RACF-ES-000530'
  tag gtitle: 'SRG-OS-000255-GPOS-00096'
  tag fix_id: 'F-25361r514789_fix'
  tag 'documentable'
  tag legacy: ['V-98107', 'SV-107211']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
