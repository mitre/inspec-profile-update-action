control 'SV-217285' do
  title 'The SUSE operating system must off-load rsyslog messages for networked systems in real time and off-load standalone systems at least weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify that the SUSE operating system must off-load rsyslog messages for networked systems in real time and off-load standalone systems at least weekly.

For stand-alone hosts, verify with the System Administrator that the log files are off-loaded at least weekly.

For networked systems, check that rsyslog is sending log messages to a remote server with the following command:

# sudo grep "\\*.\\*" /etc/rsyslog.conf | grep "@" | grep -v "^#"

*.*;mail.none;news.none @192.168.1.101:514

If any active message labels in the file do not have a line to send log messages to a remote server, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to off-load rsyslog messages for networked systems in real time.

For stand-alone systems establish a procedure to off-load log messages at least once a week.

For networked systems add a "@[Log_Server_IP_Address]" option to every active message label in "/etc/rsyslog.conf" that does not have one. Some examples are listed below:

*.*;mail.none;news.none -/var/log/messages
*.*;mail.none;news.none @192.168.1.101:514

An additional option is to capture all of the log messages and send them to a remote log host:

*.* @@loghost:514'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18513r370011_chk'
  tag severity: 'medium'
  tag gid: 'V-217285'
  tag rid: 'SV-217285r854163_rule'
  tag stig_id: 'SLES-12-030340'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-18511r370012_fix'
  tag 'documentable'
  tag legacy: ['V-77483', 'SV-92179']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
