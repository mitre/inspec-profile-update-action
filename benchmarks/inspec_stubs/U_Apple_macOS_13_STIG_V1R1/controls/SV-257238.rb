control 'SV-257238' do
  title 'The macOS system must be configured with system log files set to mode 640 or less permissive.'
  desc 'System logs must only be readable by root or admin users. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct permissions mitigates this risk.'
  desc 'check', %q(Verify the macOS system is configured with system log files set to mode 640 or less with the commands below.

These commands must be run from inside "/var/log".

/usr/bin/sudo /usr/bin/stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null

/usr/bin/sudo /usr/bin/stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null

If the permissions on log files are not "640" or less permissive, this is a finding.)
  desc 'fix', 'Configure the macOS system with system log files set to mode 640 with the following command:

/usr/bin/sudo chmod 640 [log file]

Alternatively, if the file is managed by "newsyslog", find the configuration line in the directory "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and edit the mode column to be "640". Or, if the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" and add or edit the mode option to be "mode=0640".'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60923r905345_chk'
  tag severity: 'medium'
  tag gid: 'V-257238'
  tag rid: 'SV-257238r905347_rule'
  tag stig_id: 'APPL-13-004002'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-60864r905346_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
