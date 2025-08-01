control 'SV-33222' do
  title 'The process ID (PID) file must be properly secured.'
  desc 'The PidFile directive sets the file path to the process ID file to which the server records the process id of the server, which is useful for sending a signal to the server process or for checking on the health of the process. If the PidFile is placed in a writable directory, other accounts could create a denial of service attack and prevent the server from starting by creating a PID file with the same name.'
  desc 'check', 'Enter the following command:

more /usr/local/Apache2.2/conf/httpd.conf.

Review the httpd.conf file and search for the following uncommented directive:  PidFile
Note the location and name of the PID file.
If the PidFile directive is not found enabled in the conf file, use /logs as the directory containing the Scoreboard file.
Verify the permissions and ownership on the folder containing the PID file. If any user accounts other than root, auditor, or the account used to run the web server have permission to, or ownership of, this folder, this is a finding. If the PID file is located in the web server DocumentRoot this is a finding.'
  desc 'fix', 'Modify the location, permissions, and/or ownership for the PID file folder.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33765r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26305'
  tag rid: 'SV-33222r1_rule'
  tag stig_id: 'WA00530 A22'
  tag gtitle: 'WA00530'
  tag fix_id: 'F-29402r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAN-1'
end
