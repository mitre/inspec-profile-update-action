control 'SV-38212' do
  title 'The root account must not be used for direct logins.'
  desc 'Direct login with the root account prevents individual user accountability. Acceptable non-routine uses of the root account for direct login are limited to emergency maintenance, the use of single-user mode for maintenance, and situations where individual administrator accounts are not available.'
  desc 'check', 'For Trusted Mode:
Check the /tcb database to determine if root account auditing is enabled and the last login log for direct root logins. Note that for the /tcb audit flag entry that numeric values are specified as positive numbers, 0, or -1. A value of -1 indicates that the field has not been assigned a value in the database. A value of 0 indicates that auditing is not enabled. 
# getprpw -m audflg root && last root | grep -v reboot

If any direct login records for root are listed, this is a finding.

For SMSE:
Check the root AUDIT_FLAG attribute setting. Note that for the /etc/default/security file audit flag entry that numeric values are specified as 0, or 1. A value of 1 indicates that auditing is enabled. A value of 0 indicates that auditing is not enabled.
# grep AUDIT_FLAG /etc/default/security /var/adm/userdb/* && last root | grep -v reboot

If any direct login records for root are listed, this is a finding.'
  desc 'fix', 'Enforce policies requiring all root account access is attained by first logging into a user account and then becoming root (using “su”, for example). 

Note:
GEN000980 limits direct login by root to the console (requires physical access). 
GEN001120 prohibits direct root logins via SSH. GEN003850 disallows telnet access. 
GEN003830 prohibits rlogin access. 
GEN002100 prohibits .rhost PAM support. 
GEN002040 prohibits .rhosts, .shosts, hosts.equiv, or shosts.equiv system files.

Ensure that root logging is enabled.
For Trusted Mode:
# modprpw -l -m audflg=1 root

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the attribute. See the below example:
AUDIT_FLAG=1

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36290r5_chk'
  tag severity: 'medium'
  tag gid: 'V-11979'
  tag rid: 'SV-38212r2_rule'
  tag stig_id: 'GEN001020'
  tag gtitle: 'GEN001020'
  tag fix_id: 'F-31547r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
