control 'SV-253924' do
  title 'The Juniper EX switch must be configured to audit the enforcement actions used to restrict access associated with changes to the device.'
  desc 'Without auditing the enforcement of access restrictions against changes to the device configuration, it will be difficult to identify attempted attacks, and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Determine if the network device audits the enforcement actions used to restrict access associated with changes to the device. This requirement may be verified by demonstration, configuration review or validated test results.

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

If the network device does not audit the enforcement actions used to restrict access associated with changes to the device, this is a finding.'
  desc 'fix', 'Configure the network device to audit the enforcement actions used to restrict access associated with changes to the device.

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
  tag check_id: 'C-57376r843803_chk'
  tag severity: 'medium'
  tag gid: 'V-253924'
  tag rid: 'SV-253924r879754_rule'
  tag stig_id: 'JUEX-NM-000470'
  tag gtitle: 'SRG-APP-000381-NDM-000305'
  tag fix_id: 'F-57327r843804_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
