control 'SV-252532' do
  title 'The macOS system must be configured with system log files set to mode 640 or less permissive.'
  desc 'System logs should only be readable by root or admin users. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct permissions mitigates this risk.'
  desc 'check', %q(The following commands check for log files that exist on the system and print the path to the log with the corresponding permissions. Run them from inside "/var/log":

/usr/bin/sudo stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
/usr/bin/sudo stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null

Each command may return zero or more files. If the permissions on log files are not "640" or less permissive, this is a finding.)
  desc 'fix', 'For any log file that returns an incorrect permission value, run the following command:

/usr/bin/sudo chmod 640 [log file]

[log file] is the full path to the log file in question. If the file is managed by "newsyslog", find the configuration line in the directory "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and edit the mode column to be "640" or less permissive. 

If the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" and add or edit the mode option to be "mode=0640" or less permissive.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55988r816408_chk'
  tag severity: 'medium'
  tag gid: 'V-252532'
  tag rid: 'SV-252532r816493_rule'
  tag stig_id: 'APPL-12-004002'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-55938r816492_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
