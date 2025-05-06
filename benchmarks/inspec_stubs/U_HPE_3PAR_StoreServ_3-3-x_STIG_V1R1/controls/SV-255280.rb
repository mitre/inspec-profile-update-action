control 'SV-255280' do
  title 'The HPE 3PAR OS must be configured to enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

The HPE 3PAR OS can be configured to have 15 characters (or more) for minimum password length. This setting affects local user accounts only, and only has an impact when a password is changed.

Password length for externally managed users is enforced by the external identity management system (LDAP/AD). This is a dependency on HP3P-33-001500/HP3P-33-101500. The HPE 3PAR OS does not supply an interface for modification of passwords maintained by external identity management systems.'
  desc 'check', 'Verify that the minimum password length is 15 characters:

cli% showsys -d

Verify that the line containing the string "Minimum PW length" shows "15" for the length. If it is not, this is a finding.'
  desc 'fix', 'Configure the minimum password length for a value of "15":

cli%  setpassword -minlen 15

Note: The user must have super-admin privileges to perform this action.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58953r870157_chk'
  tag severity: 'medium'
  tag gid: 'V-255280'
  tag rid: 'SV-255280r870282_rule'
  tag stig_id: 'HP3P-33-001505'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-58897r870158_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
