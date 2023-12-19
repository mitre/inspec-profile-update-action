control 'SV-251247' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles.'
  desc 'check', 'Review the permissions granted to users by the operating system/file system on the database files, database log files, and database backup files. 

If any user/role who is not an authorized system administrator with a need to know or database administrator with a need to know, or a system account for running DBMS processes, is permitted to read/view any of these files, this is a finding.

Review the directory contents and files and verify that the appropriate file permissions are set. Verify that the file owner and group is set to Redis Labs or a group defined per site requirements.

To check permissions of log files (Note: This may vary depending on the installation path.):
# /var/opt/redislabs/log

To check persisted files from memory if they are being used run the following command (Note: This may vary depending on the installation path.)
# ls -ltr /var/opt/redislabs/persist/redis/  

To check the default file permissions to verify that all authenticated users can only read and modify their own files:
# cat/etc/login.defs|grep UMASK

Verify the value is set to 077 or an appropriate organizationally defined setting.

Investigate the permissions on these files. If the permissions allow access by other, this is a finding.'
  desc 'fix', 'Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the line for the "UMASK" parameter in "/etc/login.defs" file to "077":

UMASK 077

Set the permissions of the log files (/var/opt/redislabs/log) and persisted files (/var/opt/redislabs/persist/redis/) to an appropriate organizationally defined setting.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54682r804929_chk'
  tag severity: 'medium'
  tag gid: 'V-251247'
  tag rid: 'SV-251247r804931_rule'
  tag stig_id: 'RD6X-00-011500'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-54636r804930_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
