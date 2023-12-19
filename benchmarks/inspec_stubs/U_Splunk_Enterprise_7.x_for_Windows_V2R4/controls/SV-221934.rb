control 'SV-221934' do
  title 'When Splunk Enterprise is distributed over multiple servers, each server must be configured to disable non-essential capabilities.'
  desc 'Applications are capable of providing a wide variety of functions and services. Some of the functions and services may not be necessary to support the configuration. This becomes more of an issue in distributed environments, where the application functions are spread out over multiple servers.

These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.'
  desc 'check', 'If the Splunk Installation is not distributed among multiple servers, this check is N/A.

If the machine being reviewed is not designated as a search head, check the following file in the Splunk installation folders:

$SPLUNK_HOME/etc/system/local/web.conf

Check for the following lines:

[settings]
startwebserver = 0

If the startwebserver = 0 line is missing, or is = 1, this is a finding.

If the machine being reviewed is not designated as an indexer, check the following file in the Splunk installation folders:

$SPLUNK_HOME/etc/system/local/indexes.conf

If this file exists, this is a finding. 

This file should only exist on an instance designated as an indexer.'
  desc 'fix', 'If the Splunk Installation is not distributed among multiple servers, this fix is N/A.

Select Settings >> Monitoring Console.

In the Monitoring Console, select Settings >> General Setup.

Set the Mode type based on the implementation design.

If Mode is set to Distributed, set each instance only with the server roles necessary for the desired functions.

On instances not designated as search heads, disable the web UI by using the following command:

./splunk disable webserver

On instances not designated as indexers, remove the file:

$SPLUNK_HOME/etc/system/local/indexes.conf'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23648r420270_chk'
  tag severity: 'medium'
  tag gid: 'V-221934'
  tag rid: 'SV-221934r879587_rule'
  tag stig_id: 'SPLK-CL-000090'
  tag gtitle: 'SRG-APP-000141-AU-000090'
  tag fix_id: 'F-23637r420271_fix'
  tag 'documentable'
  tag legacy: ['SV-111321', 'V-102369']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
