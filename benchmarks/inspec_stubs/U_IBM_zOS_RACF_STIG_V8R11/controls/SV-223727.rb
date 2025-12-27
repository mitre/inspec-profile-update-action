control 'SV-223727' do
  title 'IBM RACF SETROPTS PASSWORD(INTERVAL) must be set to 60 days.'
  desc "Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised. INTERVAL specifies the maximum number of days that each user's password is valid. When a user logs on to the system, RACF compares the system password interval value specified in the user profile. RACF uses the lower of the two values to determine if the users password has expired."
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts List

If the PASSWORD(INTERVAL) value is set properly and the message is PASSWORD CHANGE INTERVAL IS 060 DAYS, this is not a finding.'
  desc 'fix', %q(Configure PASSWORD(INTERVAL) SETROPTS value to "060" days. This specifies the maximum number of days that each user's password is valid.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including PASSWORD INTERVAL. 

Setting the password interval to 60 days is activated with the command SETR PASSWORD(INTERVAL(60)).)
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25400r868824_chk'
  tag severity: 'medium'
  tag gid: 'V-223727'
  tag rid: 'SV-223727r868826_rule'
  tag stig_id: 'RACF-ES-000800'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-25388r868825_fix'
  tag 'documentable'
  tag legacy: ['SV-107265', 'V-98161']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
