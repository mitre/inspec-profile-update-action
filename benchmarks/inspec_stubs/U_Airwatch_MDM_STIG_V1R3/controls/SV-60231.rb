control 'SV-60231' do
  title 'The AirWatch MDM Server must back up audit records on an organization-defined frequency onto a different system or media than the system being audited.'
  desc 'Protection of log data includes assuring the log data is not accidentally lost or deleted.  Backing up audit records to a different system or onto separate media other than the system being audited on an organizationally-defined frequency helps to assure in the event of a catastrophic system failure, the audit records will be retained.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server backs up audit records on an organization-defined frequency onto a different system or media other than the system being audited. If the AirWatch MDM Server does not back up audit records on an organization-defined frequency onto a different system or media other than the system being audited, this is a finding.

To verify the exporting of specific information collected by the AirWatch application to an external auditing or reporting system: click the (1) "Menu" button from top tool bar, (2) click on "System Configuration" under "Configuration" heading, (3) click on "System" on left-hand tool bar, (4) click on "Enterprise Integration", (5) click on "Syslog", and (6) verify proper configuration information. (7) Check report output on external system to verify functionality.'
  desc 'fix', 'Configure the AirWatch MDM Server to back up audit records on an organization-defined frequency onto a different system or media other than the system being audited.

To export auditing information to external reporting system:  click the (1) "Menu" button from top tool bar, (2) click on "System Configuration" under "Configuration" heading, (3) click on "System" on left-hand tool bar, (4) click on "Enterprise Integration", (5) click on "Syslog", and (6) enter in information for applicable destination logging server in box labeled "Message Content".  (7) Click "Save".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50125r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47359'
  tag rid: 'SV-60231r1_rule'
  tag stig_id: 'ARWA-02-000258'
  tag gtitle: 'SRG-APP-125-MDM-274-SRV'
  tag fix_id: 'F-51065r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
