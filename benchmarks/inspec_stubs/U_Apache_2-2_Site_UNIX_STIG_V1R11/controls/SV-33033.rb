control 'SV-33033' do
  title 'Log file access must be restricted to System Administrators, Web Administrators or Auditors.'
  desc 'A major tool in exploring the web site use, attempted use, unusual conditions, and problems are the access and error logs. In the event of a security incident, these logs can provide the SA and the web manager with valuable information. To ensure the integrity of the log files and protect the SA and the web manager from a conflict of interest related to the maintenance of these files, only the members of the Auditors group will be granted permissions to move, copy, and delete these files in the course of their duties related to the archiving of these files.'
  desc 'check', 'Enter the following command to determine the directory the log files are located in:

grep "ErrorLog" /usr/local/apache2/conf/httpd.conf

grep "CustomLog" /usr/local/apache2/conf/httpd.conf

Verify the permission of the ErrorLog & CustomLog files by entering the following command:

ls -al /usr/local/apache2/logs/*.log 

Unix file permissions should be 640 or less for all web log files if not, this is a finding.'
  desc 'fix', 'Use the chmod command to set the appropriate file permissions on the log files.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33716r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2252'
  tag rid: 'SV-33033r1_rule'
  tag stig_id: 'WG250 A22'
  tag gtitle: 'WG250'
  tag fix_id: 'F-29348r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
