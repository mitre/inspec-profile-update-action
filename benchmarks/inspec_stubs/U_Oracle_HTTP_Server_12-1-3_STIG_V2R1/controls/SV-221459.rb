control 'SV-221459' do
  title 'OHS must have the ScoreBoardFile directive disabled.'
  desc 'The ScoreBoardFile directive sets a file path which the server will use for Inter-Process Communication (IPC) among the Apache processes. If the directive is specified, then Apache will use the configured file for the inter-process communication. Therefore if it is specified it needs to be located in a secure directory. If the ScoreBoard file is placed in openly writable directory, other accounts could create a denial of service attack and prevent the server from starting by creating a file with the same name, and or users could monitor and disrupt the communication between the processes by reading and writing to the file.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "ScoreBoardFile" directive at the server configuration scope.

3. If the "ScoreBoardFile" directive exists, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "ScoreBoardFile" directive at the server configuration scope.

3. Remove the "ScoreBoardFile" directive.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23174r415060_chk'
  tag severity: 'medium'
  tag gid: 'V-221459'
  tag rid: 'SV-221459r415062_rule'
  tag stig_id: 'OH12-1X-000222'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23163r415061_fix'
  tag 'documentable'
  tag legacy: ['SV-79171', 'V-64681']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
