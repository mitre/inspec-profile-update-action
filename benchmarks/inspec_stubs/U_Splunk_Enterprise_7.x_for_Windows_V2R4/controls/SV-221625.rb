control 'SV-221625' do
  title 'Splunk Enterprise must be configured to send an immediate alert to the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated log record storage volume reaches 75 percent of the repository maximum log record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75 percent they are unable to plan for storage capacity expansion. 

Although this may be part of the operating system function, for the enterprise events management system, this is most often a function managed through the application since it is a critical function and requires the use of a large amount of external storage.'
  desc 'check', 'Perform the following checks. If any do not comply, this is a finding.

(Note that these files may exist in one of the following folders or its subfolders:
$SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/etc/slave-apps/)

1. Examine the file in the Splunk installation folder:

$SPLUNK_HOME/etc/system/local/server.conf

Locate the following setting:

[diskUsage]
minFreeSpace =  xxxx

Verify that the value is set to 25 percent of the size of the storage volume. For example, 25 percent of a 100 GB drive is 25 GB, and the value set would be 25000, as the value is in megabytes.

2. Examine the file in the Splunk installation folder:

$SPLUNK_HOME/etc/system/local/health.conf

Locate the following setting:

[alert_action:email]
disabled = 0
action.to =
action.cc =

Verify that the email addresses of the ISSO and SA are set to receive alerts. This email address can be a group address (example alerts@domain.com) that contains the addresses of the ISSO and SA.

3. In the Splunk console, select Settings >> Health Report Manager >> feature:disk_space.

Verify Red setting is 1, and Yellow setting is 2.'
  desc 'fix', 'Perform the following fixes.

(Note that these files may exist in one of the following folders or its subfolders:
$SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/etc/slave-apps/)

1. Edit the file in the Splunk installation folder:

$SPLUNK_HOME/etc/system/local/server.conf

Add the following lines:

[diskUsage]
minFreeSpace =  xxxx

Set the value to 25 percent of the size of the storage volume. For example, 25 percent of a 100 GB drive is 25 GB, and the value set would be 25000, as the value is in megabytes.

2. Examine the file in the Splunk installation folder:

$SPLUNK_HOME/etc/system/local/health.conf

Add the following lines:

[alert_action:email]
disabled = 0
action.to =
action.cc =

Set the email addresses of the ISSO and SA to be able to receive alerts. This email address can be a group address (example alerts@domain.com) that contains the addresses of the ISSO and SA.

3. In the Splunk console, select Settings >> Health Report Manager >> feature:disk_space.

Set the Red setting to 1, and Yellow setting to 2.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23340r416332_chk'
  tag severity: 'low'
  tag gid: 'V-221625'
  tag rid: 'SV-221625r879732_rule'
  tag stig_id: 'SPLK-CL-000290'
  tag gtitle: 'SRG-APP-000359-AU-000120'
  tag fix_id: 'F-23329r416333_fix'
  tag 'documentable'
  tag legacy: ['SV-111341', 'V-102397']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
