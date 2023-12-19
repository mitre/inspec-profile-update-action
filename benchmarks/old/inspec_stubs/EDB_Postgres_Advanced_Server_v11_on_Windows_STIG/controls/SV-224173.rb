control 'SV-224173' do
  title 'The EDB Postgres Advanced Server password file must not be used.'
  desc 'The EDB Postgres password file can contain passwords to be used if the connection allows a password (and no password has been specified otherwise). 

This file contain lines of the following format:
hostname:port:database:username:password

It is critically important to system security that use of a password file be avoided as it stores passwords in plain text. Any user with access to these could potentially compromise the security of the database.'
  desc 'check', "Check DBMS settings to determine whether a password file is being used.

On Windows the default file name and location is:
%APPDATA%\\postgresql\\pgpass.conf (where %APPDATA% refers to the Application Data subdirectory in the user's profile). 
Alternatively, a password file can be specified using the connection parameter passfile or the environment variable PGPASSFILE.

If a password file exists, this is a finding.
If a password file is not in use, this is not a finding."
  desc 'fix', 'Remove any password files present on the server and implement a  more secure form of authentication.

The DoD standard for authentication is DoD-approved PKI certificates.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25846r495537_chk'
  tag severity: 'medium'
  tag gid: 'V-224173'
  tag rid: 'SV-224173r508023_rule'
  tag stig_id: 'EP11-00-004850'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-25834r495538_fix'
  tag 'documentable'
  tag legacy: ['SV-110213', 'V-101109']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
