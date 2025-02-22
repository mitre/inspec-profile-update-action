control 'SV-253887' do
  title 'The Juniper EX switch must be configured to protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by nonrepudiation.'
  desc 'This requirement supports nonrepudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Determine if the network device protects against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by nonrepudiation. This requires logging all administrator access and configuration activity. This requirement may be verified by demonstration or configuration review. This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server. (Note that two-factor authentication of administrator access is needed to support this requirement.) 

Verify the system logs the facility "any", or minimally "change-log" and "interactive-commands", and the logging level is appropriate. Generally, the "all" (debug) logging level should be avoided because the number of logged messages is significant.

[edit system syslog]
host <IPv4 or IPv6 syslog address> {
    any info;
}
file <file name> {
    change-log info;
    interactive-commands info;
}
Note: If minimally logging only configuration changes, there will be other files receiving the events from the other logging facilities (for example "authorizations" or "firewall").

Syslog outputs in standard format unless the "structured-data" directive is configured. Verify the "structured-data" command for all files and external syslog servers requiring that format. For example:

[edit system syslog]
host <IPv4 or IPv6 syslog address> {
    change-log info;
    interactive-commands info;
    structured-data;
}
file <file name> {
    any info;
    structured-data;
}

If the network device does not protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by nonrepudiation, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by nonrepudiation. Examples that support this include configuring the audit log to capture administration login events and configuration changes to the network device.

set system syslog host <IPv4 or IPv6 syslog address> change-log info
set system syslog host <IPv4 or IPv6 syslog address> interactive-commands info
-or-
set system syslog host <IPv4 or IPv6 syslog address> any info

set system syslog file <file name> change-log info
set system syslog file <file name> interactive-commands info
-or-
set system syslog file <file name> any info'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57339r843692_chk'
  tag severity: 'medium'
  tag gid: 'V-253887'
  tag rid: 'SV-253887r843694_rule'
  tag stig_id: 'JUEX-NM-000100'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-57290r843693_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
