control 'SV-221835' do
  title 'The Oracle Linux operating system must send rsyslog output to a log aggregation server.'
  desc 'Sending rsyslog output to another system ensures that the logs cannot be removed or modified in the event that the system is compromised or has a hardware failure.'
  desc 'check', 'Verify "rsyslog" is configured to send all messages to a log aggregation server.

Check the configuration of "rsyslog" with the following command:

Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf".

     # grep @ /etc/rsyslog.conf /etc/rsyslog.d/*.conf

     *.* @@[logaggregationserver.example.mil]:[port]

If there are no lines in the "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files that contain the "@" or "@@" symbol(s), and the lines with the correct symbol(s) to send output to another system do not cover all "rsyslog" output, ask the system administrator to indicate how the audit logs are offloaded to a different system or media. 

If the lines are commented out or there is no evidence that the audit logs are being sent to another system, this is a finding.'
  desc 'fix', 'Modify the "/etc/rsyslog.conf" or an "/etc/rsyslog.d/*.conf" file to contain a configuration line to send all "rsyslog" output to a log aggregation server:

For UDP:
     *.* @[logaggregationserver.example.mil]:[port]

For TCP: 
     *.* @@[logaggregationserver.example.mil]:[port]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23550r917852_chk'
  tag severity: 'medium'
  tag gid: 'V-221835'
  tag rid: 'SV-221835r917854_rule'
  tag stig_id: 'OL07-00-031000'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23539r917853_fix'
  tag 'documentable'
  tag legacy: ['SV-108513', 'V-99409']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
