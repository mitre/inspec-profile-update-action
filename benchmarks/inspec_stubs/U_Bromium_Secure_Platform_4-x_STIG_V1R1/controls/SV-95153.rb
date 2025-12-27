control 'SV-95153' do
  title 'The Bromium Enterprise Controller (BEC) must send log records to a central log server (i.e., syslog server).'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

This requirement requires that the content captured in audit records be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application components requiring centralized audit log management must have the capability to support centralized management.

Note: The central log server must be configured with alerts and notifications that are required by the various requirements in this STIG. It must also be configured to alert the ISSO and system administrator when communications is lost with the BEC.'
  desc 'check', 'Verify that a syslog destination is configured on the BEC server.

1. From the management console, click the selection arrow next to "Events".
2. Click "Destinations".
3. Inspect the list of configured syslog destinations.

If the BEC does not automatically forward events to a  syslog destination, this is a finding.'
  desc 'fix', 'Configure the BEC to automatically forward events to the desired syslog destination.

1. From the management console, click on the selection arrow next to "Events".
2. Click on "Destinations".
3. Click on "Add Syslog Destination".
4. Configure syslog server parameters and select severity levels to forward.
5. Click "Save ".

Additional syslog destinations may be configured for forwarding events to multiple destinations simultaneously.'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80121r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80449'
  tag rid: 'SV-95153r1_rule'
  tag stig_id: 'BROM-00-000760'
  tag gtitle: 'SRG-APP-000356'
  tag fix_id: 'F-87255r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
