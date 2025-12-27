control 'SV-213512' do
  title 'JBoss ROOT logger must be configured to utilize the appropriate logging level.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes: time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked. 

See Chapter 14, Section 14.1.9, Table 14.4 of the Red Hat JBoss EAP Administration and Configuration Guide version 6.3 for specific details on log levels and log level values.

The JBOSS application server ROOT logger captures all messages not captured by a log category and sends them to a log handler (FILE, CONSOLE, SYSLOG, ETC.).  By default, the ROOT logger level is set to INFO, which is a value of 800.  This will capture most events adequately.  Any level numerically higher than INFO (> 800) records less data and may result in an insufficient amount of information being logged by the ROOT logger.  This can result in failed forensic investigations.  The ROOT logger level must be INFO level or lower to provide adequate log information.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script to start the Command Line Interface (CLI).
Connect to the server and authenticate.

The PROFILE NAMEs included with a Managed Domain JBoss configuration are:
"default", "full", "full-ha" or "ha"
For a Managed Domain configuration, you must check each profile name:

For each PROFILE NAME, run the command:
"ls /profile=<PROFILE NAME>/subsystem=logging/root-logger=ROOT"

If ROOT logger "level" is not set to INFO, DEBUG or TRACE
This is a finding for each <PROFILE NAME> (default, full, full-ha and ha)

For a Standalone configuration:
"ls /subsystem=logging/root-logger=ROOT"

If "level" not = INFO, DEBUG or TRACE, this is a finding.'
  desc 'fix', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script to start the Command Line Interface (CLI).
Connect to the server and authenticate.

The PROFILE NAMEs included with a Managed Domain JBoss configuration are:
"default", "full", "full-ha" or "ha"
For a Managed Domain configuration, you must check each profile name:

For each PROFILE NAME, run the command:
"/profile=<PROFILE NAME>/subsystem=logging/root-logger=ROOT:write-attribute(name=level,value=INFO)"

For a Standalone configuration:
"/subsystem=logging/root-logger=ROOT:write-attribute(name=level,value=INFO)"'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14735r296202_chk'
  tag severity: 'medium'
  tag gid: 'V-213512'
  tag rid: 'SV-213512r615939_rule'
  tag stig_id: 'JBOS-AS-000135'
  tag gtitle: 'SRG-APP-000100-AS-000063'
  tag fix_id: 'F-14733r296203_fix'
  tag 'documentable'
  tag legacy: ['SV-76739', 'V-62249']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
