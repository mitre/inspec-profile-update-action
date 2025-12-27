control 'SV-33135' do
  title 'Log file access must be restricted to System Administrators, Web Administrators or Auditors.'
  desc 'A major tool in exploring the web site use, attempted use, unusual conditions and problems are the access and error logs. In the event of a security incident, these logs can provide the SA and Web
Manager with valuable information. To ensure the integrity of the log files and protect the SA and Web
Manager from a conflict of interest related to the maintenance of these files, only the members of the
Auditors group will be granted permissions to move, copy and delete these files in the course of their
duties related to the archiving of these files.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directives:  ErrorLog & CustomLog

Navigate to the location of the file specified after each enabled ErrorLog & CustomLog directive and verify the permissions assigned to these files. Right click on the file to be examined. Select Properties > Select the “Security” tab. Permissions greater than Read & Execute should be allowed for only the account assigned to the Apache server service, and the Auditors Group. If the SA, Web Manager or users other than the Auditors group have greater than read access to the log files, this is a finding. If anyone other than the Auditors, Administrators, Web Managers, or the account assigned to the Apache server service has access to the log files, this is a finding.'
  desc 'fix', 'Remove the unauthorized permissions from the applicable accounts.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33787r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2252'
  tag rid: 'SV-33135r1_rule'
  tag stig_id: 'WG250 W22'
  tag gtitle: 'WG250'
  tag fix_id: 'F-29431r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
