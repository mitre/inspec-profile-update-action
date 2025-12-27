control 'SV-257237' do
  title 'The macOS system must be configured with system log files owned by root and group-owned by wheel or admin.'
  desc 'System logs must only be readable by root or admin users. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct owner mitigates this risk.

Some system log files are controlled by "newsyslog" and "aslmanager".'
  desc 'check', %q(Verify the macOS system is configured with system log files owned by root or a service account and group-owned by wheel or admin with the commands below. 

These commands must be run from inside "/var/log".

/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null

/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null

If there are any system log files that are not owned by "root" or a service account and group-owned by "wheel" or "admin", this is a finding.)
  desc 'fix', 'Configure the macOS system with system log files owned by root or a service account and group-owned by wheel or admin with the following command:

/usr/bin/sudo chown root:wheel [log file]

Alternatively, if the file is managed by "newsyslog", find the configuration line in the directory "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and ensure the owner:group column is set to "root:wheel" or the appropriate service account and group. 

If the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" and ensure that "uid" and "gid" options are set to a service account and group, respectively.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60922r905342_chk'
  tag severity: 'medium'
  tag gid: 'V-257237'
  tag rid: 'SV-257237r905344_rule'
  tag stig_id: 'APPL-13-004001'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-60863r905343_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
