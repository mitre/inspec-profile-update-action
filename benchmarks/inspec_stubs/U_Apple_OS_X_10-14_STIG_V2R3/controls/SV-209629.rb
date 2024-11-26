control 'SV-209629' do
  title 'The macOS system must be configured with system log files owned by root and group-owned by wheel or admin.'
  desc 'System logs should only be readable by root or admin users. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct owner mitigates this risk.'
  desc 'check', %q(Log files are controlled by "newsyslog" and "aslmanager".

These commands check for log files that exist on the system and print out the log with corresponding ownership. Run them from inside "/var/log":

/usr/bin/sudo stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
/usr/bin/sudo stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null

If there are any system log files that are not owned by "root" and group-owned by "wheel" or admin, this is a finding.

Service logs may be owned by the service user account or group.)
  desc 'fix', 'For any log file that returns an incorrect owner or group value, run the following command:

/usr/bin/sudo chown root:wheel [log file]

[log file] is the full path to the log file in question. If the file is managed by "newsyslog", find the configuration line in the directory "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and ensure that the owner:group column is set to "root:wheel" or the appropriate service user account and group. 

If the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" and ensure that "uid" and "gid" options are either not present or are set to a service user account and group respectively.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9880r466291_chk'
  tag severity: 'medium'
  tag gid: 'V-209629'
  tag rid: 'SV-209629r610285_rule'
  tag stig_id: 'AOSX-14-004001'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-9880r466292_fix'
  tag 'documentable'
  tag legacy: ['V-95987', 'SV-105125']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
