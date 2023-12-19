control 'SV-209630' do
  title 'The macOS system must be configured with system log files set to mode 640 or less permissive.'
  desc 'System logs should only be readable by root or admin users. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct permissions mitigates this risk.'
  desc 'check', %q(These commands check for log files that exist on the system and print out the log with corresponding permissions. Run them from inside "/var/log":

/usr/bin/sudo stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
/usr/bin/sudo stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null

The correct permissions on log files should be "640" or less permissive for system logs. 

Any file with more permissive settings is a finding.)
  desc 'fix', 'For any log file that returns an incorrect permission value, run the following command:

/usr/bin/sudo chmod 640 [log file]

[log file] is the full path to the log file in question. If the file is managed by "newsyslog", find the configuration line in the directory "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and edit the mode column to be "640" or less permissive. 

If the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" and add or edit the mode option to be "mode=0640" or less permissive.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9881r466294_chk'
  tag severity: 'medium'
  tag gid: 'V-209630'
  tag rid: 'SV-209630r610285_rule'
  tag stig_id: 'AOSX-14-004002'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-9881r466295_fix'
  tag 'documentable'
  tag legacy: ['SV-105127', 'V-95989']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
