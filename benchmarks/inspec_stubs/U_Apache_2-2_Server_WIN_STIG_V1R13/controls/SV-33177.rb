control 'SV-33177' do
  title 'The process ID (PID) file must be properly secured.'
  desc 'The PidFile directive sets the path to the process ID file to which the server records the process ID of the server, which is useful for sending a signal to the server process or for checking on the health of the process. If the PidFile is placed in a writable directory, other accounts could create a denial of service attack and prevent the server from starting by creating a PID file with the same name.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as Notepad, and search for the following directive: PidFile

Note the location and name of the PID file
If the PID file location is not specified in the conf file, use the \\logs directory as the PID file location.

Verify the permissions on the folder containing the PID file. If any user accounts other than administrator, auditor, or the account used to run the web server has permission to this file, this is a finding. If the PID file is located in the web server DocumentRoot this is a finding.'
  desc 'fix', 'Modify the location and/or permissions for the PID file and/or folder.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26305'
  tag rid: 'SV-33177r1_rule'
  tag stig_id: 'WA00530 W22'
  tag gtitle: 'WA00530'
  tag fix_id: 'F-29461r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
