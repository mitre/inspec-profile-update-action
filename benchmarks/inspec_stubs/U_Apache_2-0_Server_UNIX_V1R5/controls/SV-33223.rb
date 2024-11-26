control 'SV-33223' do
  title 'The score board file must be properly secured.'
  desc 'The ScoreBoardfile directive sets a file path which the server will use for Inter-Process Communication (IPC) among the Apache processes.  If the directive is specified, then Apache will use the configured file for the inter-process communication. Therefore if it is specified it needs to be located in a secure directory. If the ScoreBoardfile is placed in a writable directory, other accounts could create a denial of service attack and prevent the server from starting by creating a file with the same name, and or users could monitor and disrupt the communication between the processes by reading and writing to the file.'
  desc 'check', 'To determine the location of the file enter the following command:

find / -name ScoreBoard.

To view the permissions on the file enter the following command:

ls -lL /path/of/ScoreBoard.

If the permissions on the file are not set to 644 or less restrictive, this is a finding.'
  desc 'fix', 'The scoreboard file is created when the server starts, and is deleted when it shuts down, set the permissions during the creation of the file.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33778r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26322'
  tag rid: 'SV-33223r1_rule'
  tag stig_id: 'WA00535 A22'
  tag gtitle: 'WA00535'
  tag fix_id: 'F-29415r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAN-1'
end
