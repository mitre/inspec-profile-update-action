control 'SV-251669' do
  title 'Splunk Enterprise must be configured to send an immediate alert to the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated log record storage volume reaches 75 percent of the repository maximum log record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion. 

Although this may be part of the operating system function, for the enterprise events management system, this is most often a function managed through the application since it is a critical function and requires the use of a large amount of external storage.'
  desc 'check', 'Perform the following checks. If any do not comply, this is a finding.

1. Examine the file in the Splunk installation folder:

$SPLUNK_HOME/etc/system/local/server.conf

Locate the following setting:

[diskUsage]
minFreeSpace = xxxx

Verify that the value is set to 25 percent of the size of the storage volume. For example, 25 percent of a 100GB drive is 25GB, and the value set would be 25000, as the value is in megabytes.

2. Examine the file in the Splunk installation folder:

$SPLUNK_HOME/etc/system/local/health.conf

Locate the following setting:

[alert_action:email]
disabled = 0
action.to =
action.cc =

Verify that the email addresses of the ISSO and SA are set to receive alerts. This email address can be a group address (example alerts@domain.com) that contain the addresses of the ISSO and SA.

3. In the Splunk console, select Settings >> Health Report Manager >> feature:disk_space.

Verify Red setting is 1, and Yellow setting is 2.'
  desc 'fix', 'Perform the following fixes.

1. Edit the file in the Splunk installation folder:

$SPLUNK_HOME/etc/system/local/server.conf

Add the following lines:

[diskUsage]
minFreeSpace = xxxx

Set the value to 25 percent of the size of the storage volume. For example, 25 percent of a 100GB drive is 25GB, and the value set would be 25000, as the value is in megabytes.

2. Examine the file in the Splunk installation folder:

$SPLUNK_HOME/etc/system/local/health.conf

Add the following lines:

[alert_action:email]
disabled = 0
action.to =
action.cc =

Set the email addresses of the ISSO and SA to be able to receive alerts. This email address can be a group address (example alerts@domain.com) that contain the addresses of the ISSO and SA.

3. In the Splunk console, select Settings >> Health Report Manager >> feature:disk_space.

Set the Red setting to 1, and Yellow setting to 2.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55107r819092_chk'
  tag severity: 'low'
  tag gid: 'V-251669'
  tag rid: 'SV-251669r879732_rule'
  tag stig_id: 'SPLK-CL-000160'
  tag gtitle: 'SRG-APP-000359-AU-000120'
  tag fix_id: 'F-55061r819093_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
