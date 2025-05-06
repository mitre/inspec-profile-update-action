control 'SV-33178' do
  title 'The ScoreBoard file must be properly secured.'
  desc 'The ScoreBoardFile directive sets a file path which the server will use for Inter-Process Communication (IPC) among the Apache processes. If the directive is specified, then Apache will use the configured file for the inter-process communication. Therefore if it is specified it needs to be located in a secure directory. If the ScoreBoard file is placed in openly writable directory, other accounts could create a denial of service attack and prevent the server from starting by creating a file with the same name, and or users could monitor and disrupt the communication between the processes by reading and writing to the file.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: ScoreBoardFile

If the ScoreBoardFile directive is found uncommented note the directory specified in the directive statement that holds the Scoreboard file.  If the ScoreBoardFile directive is not found enabled in the conf file use \\logs as the directory containing the Scoreboard file.

If any users other than administrator or the account used to run the web server has permission to the scoreboard file directory, this is a finding. If the ScoreBoard file is located in the web server document root this is finding.'
  desc 'fix', 'Modify the location and/or permissions for the ScoreBoard file and/or folder.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33812r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26322'
  tag rid: 'SV-33178r2_rule'
  tag stig_id: 'WA00535 W22'
  tag gtitle: 'WA00535'
  tag fix_id: 'F-29463r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
