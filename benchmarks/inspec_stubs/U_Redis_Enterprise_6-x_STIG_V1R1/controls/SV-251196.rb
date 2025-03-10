control 'SV-251196' do
  title 'Redis Enterprise DBMS must offload audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility, and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity. 

The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with offloading the records to the centralized system.

For more information, refer to: 
https://docs.redislabs.com/latest/rs/administering/logging/rsyslog-logging/
and
https://redislabs.com/blog/sending-redis-cluster-alerts-to-slack-with-syslog/'
  desc 'check', 'Review the system documentation for a description of how audit records are offloaded. By default, all log entries shown on the log page in the Redis Enterprise UI are also written to syslog. Then, rsyslog can be configured to monitor the syslog. All alerts are logged to syslog if the alerts are configured to be enabled, in addition to other log entries. These logs can be configured to be offloaded to a centralized log management system.

Verify that Redis Enterprise is configured on the server to send all logs to a centralized log management system by examining the redislabs.conf file found in /etc/rsyslog.d.

The file should include the line:
     action(type="omfwd" protocol="tcp" target="[organization defined logging server IP]" port="[organization defined logging server port]" template="RedisLabsEventTemplate" )

If it does not, this is a finding.

If the DBMS has a continuous network connection to the centralized log management system, but the DBMS audit records are not written directly to the centralized log management system or transferred in near-real-time, this is a finding.

If the DBMS does not have a continuous network connection to the centralized log management system, and the DBMS audit records are not transferred to the centralized log management system weekly or more often, this is a finding.'
  desc 'fix', %q(Configure Redis Enterprise to offload log entries onto a separate log server by configuring the redislabs.conf and ensuring that all server logs from syslog are offloaded to a centralized backup server.

To configure Redis Enterprise to use syslog for all logs generated, ensure that redislabs.conf exists and is configured.

Create the file as shown here:
/etc/rsyslog.d/redislabs.conf

The log entries can be categorized into events and alerts. Events are only logged, while alerts have a state attached to them. RS log entries include information about the specific event that occurred. In addition, rsyslog can be configured to add other information, such as the event severity, for example.

Since rsyslog entries do not include the severity information by default, use the following instructions to log that information (in Ubuntu): 
Add the following line to /etc/rsyslog.conf $template TraditionalFormatWithPRI,"%pri-text%:%timegenerated%:%HOSTNAME%:%syslogtag%:%msg:::drop-last-lf%\n"

And modify $ActionFileDefaultTemplate to use the new template: $ActionFileDefaultTemplateTraditionalFormatWithPRI 

Save the changes and restart rsyslog for the changes to take effect. Alerts and events can be viewed under /var/log in messages log file.

Command components:
%pri­text% ­adds the severity.
%timegenerated% ­adds the timestamp.
%HOSTNAME% ­adds the machine name.
%syslogtag% ­the RS message as detailed below in the Log entry structure section below.
%msg:::drop­last­lf%n ­ removes duplicated log entries.

Example configuration:
template(name="RedisLabsEventTemplate" type="string" string="%syslogseverity-text%:%pri-text%:%timegenerated%:%HOSTNAME%:%syslogtag%:%msg:::drop-last-lf% -- %syslogtag%  -- %programname% \n")

if $programname startswith 'event_log' then {
  action(type="omfile" file="/var/log/redislabs.log" template="RedisLabsEventTemplate" )
}

With this configuration, the syslog service will:
Load a new template named RedisLabsEventTemplate that logs the message with the priority (syslogseverity-text) that will be info, crit, warning, etc.

Use this template to write into the file /var/log/redislabs.log when the program is "event_log" (the Redis Enterprise log manager). Learn more about the template syntax in the syslog documentation. 

Restart syslog: systemctl restart rsyslog

Testing the new configuration:
Navigate to the Redis Enterprise web console and create a new database (or edit an existing database). There should be a new /var/log/redislabs.log file and the event that was generated.)
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54631r804776_chk'
  tag severity: 'medium'
  tag gid: 'V-251196'
  tag rid: 'SV-251196r806443_rule'
  tag stig_id: 'RD6X-00-005600'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-54585r806442_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
