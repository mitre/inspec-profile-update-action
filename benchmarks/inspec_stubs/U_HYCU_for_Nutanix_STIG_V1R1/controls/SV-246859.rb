control 'SV-246859' do
  title 'The HYCU Web UI must be configured to send log data to a central log server for forwarding alerts to the administrators and the ISSO.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', "Log on to the HYCU Web UI and verify that an SMTP server is configured under the gear menu and SMTP Server Settings. 

Verify that Email Notifications have been enabled to send predetermined alerts to an ISSO and/or HYCU Admin.
 
Verify that HYCU VM logs are being set to a central logging server by way of a mechanism that is specific to the customer's central logging server. 

If Auditors and Security Ops teams are not receiving email notifications or logs from HYCU, this is a finding."
  desc 'fix', 'Log on to the HYCU Web UI and verify that an SMTP server is configured under the gear menu and "SMTP Server Settings". 

Within the "Events" menu, click on the email notifications button and configure the items to be sent in an email notification. Ensure the correct email address is used for the individual(s) who will need to receive the notifications. 

To ship/send logs from the HYCU VM to a central logging server (e.g., Splunk, SolarWinds), engage with the log server vendor and HYCU Support. In the absence of another third-party solution, consider setting up a Rsyslog Server and make HYCU a client. 

To configure an Rsyslog client:

# in addition to existing settings (output to local log files),

# send logs to remote host, too

[root@hycuserver ~]#  vi /etc/rsyslog.conf
# add to the end

action(type="omfwd"
       queue.filename="fwdRule_customerloggingservername.local"
       queue.maxdiskspace="1g"
       queue.saveonshutdown="on"
       queue.type="LinkedList"
       action.resumeRetryCount="-1"
       Target="fwdRule_customerloggingservername.local" Port="514" Protocol="tcp")

# for the case to send specific facility logs

# for example, set [authpriv]

[root@hycuserver ~]#  vi /etc/rsyslog.conf
# comment put existing line if you do not want to output to local filesystem

#authpriv.*                   /var/log/secure
authpriv.* action(type="omfwd"
       queue.filename="fwdRule_fwdRule_customerloggingservername.local"
       queue.maxdiskspace="1g"
       queue.saveonshutdown="on"
       queue.type="LinkedList"
       action.resumeRetryCount="-1"
       Target="fwdRule_customerloggingservername.local" Port="514" Protocol="tcp")

[root@hycuserver ~]#  systemctl restart rsyslog'
  impact 0.7
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50291r768239_chk'
  tag severity: 'high'
  tag gid: 'V-246859'
  tag rid: 'SV-246859r768241_rule'
  tag stig_id: 'HYCU-SI-000001'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-50245r768240_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
