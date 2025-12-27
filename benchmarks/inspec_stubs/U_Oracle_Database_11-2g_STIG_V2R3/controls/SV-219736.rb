control 'SV-219736' do
  title 'Access to DBMS software files and directories must not be granted to unauthorized users.'
  desc 'The DBMS software libraries contain the executables used by the DBMS to operate. Unauthorized access to the libraries can result in malicious alteration or planting of operational executables. This may in turn jeopardize data stored in the DBMS and/or operation of the host system.'
  desc 'check', 'For UNIX Systems:

Log in using the Oracle software owner account and enter the command:

umask

If the value returned is 022 or more restrictive, this is not a Finding.

If the value returned is less restrictive than 022, this is a Finding.

The first number sets the mask for user/owner file permissions. The second number sets the mask for group file permissions. The third number sets file permission mask for other users. The list below shows the available settings:

0 = read/write/execute
1 = read/write
2 = read/execute
3 = read
4 = write/execute
5 = write
6 = execute
7 = no permissions

Setting the umask to 022 effectively sets files for user/owner to read/write, group to read and other to read. Directories are set for user/owner to read/write/execute, group to read/execute and other to read/execute.

For Windows Systems:
Review the permissions that control access to the Oracle installation software directories (e.g. \\Program Files\\Oracle\\).

DBA accounts, the DBMS process account, the DBMS software installation/maintenance account, SA accounts if access by them is required for some operational level of support such as backups, and the host system itself require access.

Compare the access control employed with that documented in the System Security Plan.

If access controls do not match the documented requirement, this is a Finding.

If access controls appear excessive without justification, this is a Finding.'
  desc 'fix', 'For UNIX Systems:

Set the umask of the Oracle software owner account to 022. Determine the shell being used for the Oracle software owner account:

env | grep -i shell

Startup files for each shell are as follows (located in users $HOME directory):

C-Shell (CSH) = .cshrc
Bourne Shell (SH) = .profile
Korn Shell (KSH) = .kshrc
TC Shell (TCS) = .tcshrc
BASH Shell = .bash_profile or .bashrc

Edit the shell startup file for the account and add or modify the line:

umask 022

Log off and login, then enter the umask command to confirm the setting.

NOTE: To effect this change for all Oracle processes, a reboot of the DBMS server may be required.

For Windows Systems:
Product-specific fix is pending development. Use Generic Fix listed below:

Restrict access to the DBMS software libraries to the fewest accounts that clearly require access based on job function.

Document authorized access control and justify any access grants that do not fall under DBA, DBMS process, ownership, or SA accounts.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21461r307057_chk'
  tag severity: 'medium'
  tag gid: 'V-219736'
  tag rid: 'SV-219736r401224_rule'
  tag stig_id: 'O112-BP-025400'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21460r307058_fix'
  tag 'documentable'
  tag legacy: ['SV-68283', 'V-54043']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
