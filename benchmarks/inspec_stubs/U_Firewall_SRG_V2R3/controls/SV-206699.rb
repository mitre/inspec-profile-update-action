control 'SV-206699' do
  title 'The firewall must be configured to send traffic log entries to a central audit server for management and configuration of the traffic log entries.'
  desc 'Without the ability to centrally manage the content captured in the traffic log entries, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The DoD requires centralized management of all network component audit record content. Network components requiring centralized traffic log management must have the ability to support centralized management. The content captured in traffic log entries must be managed from a central location (necessitating automation). Centralized management of traffic log records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. 

Ensure at least one syslog server is configured on the firewall.

If the product inherently has the ability to store log records locally, the local log must also be secured. However, this requirement is not met since it calls for a use of a central audit server.'
  desc 'check', "Examine the traffic log configuration on the firewall.

Verify the firewall is configured to send traffic log entries to the organization's central audit server. 

If the firewall is not configured to send traffic log entries to the organization's central audit server, this is a finding."
  desc 'fix', "Configure the firewall to ensure traffic log entries are transmitted to the organization's central audit server (e.g., syslog server)."
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6956r297876_chk'
  tag severity: 'medium'
  tag gid: 'V-206699'
  tag rid: 'SV-206699r863248_rule'
  tag stig_id: 'SRG-NET-000333-FW-000014'
  tag gtitle: 'SRG-NET-000333'
  tag fix_id: 'F-6956r297877_fix'
  tag 'documentable'
  tag legacy: ['V-79445', 'SV-94151']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
