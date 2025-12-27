control 'SV-223726' do
  title 'The IBM RACF SETROPTS PASSWORD(MINCHANGE) value must be set to 1.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts List

If the PASSWORD(MINCHANGE) value shows PASSWORD MINIMUM CHANGE INTERVAL IS <1> DAYS, this is not a finding.'
  desc 'fix', 'Configure PASSWORD(MINCHANGE) SETROPTS value number to "1". This specifies the number of days that must pass before a user can change their password.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including PASSWORD MINCHANGE. Use the following command as an example command:
SETROPTS PASSWORD(MINCHANGE(1))'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25399r514866_chk'
  tag severity: 'medium'
  tag gid: 'V-223726'
  tag rid: 'SV-223726r604139_rule'
  tag stig_id: 'RACF-ES-000790'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-25387r514867_fix'
  tag 'documentable'
  tag legacy: ['SV-107263', 'V-98159']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
