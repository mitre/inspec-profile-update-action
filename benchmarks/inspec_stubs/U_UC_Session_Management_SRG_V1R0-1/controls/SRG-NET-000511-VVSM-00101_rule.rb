control 'SRG-NET-000511-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to offload session (call) records to a central log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

This requirement only applies to components where this is specific to the function of the device (e.g., IDPS sensor logs, firewall logs). This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the Unified Communications Session Manager offloads session records to a central log server.

If the Unified Communications Session Manager does not offload session records to a central log server, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to offload session records to a central log server.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000511-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000511-VVSM-00101'
  tag rid: 'SRG-NET-000511-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000511-VVSM-00101'
  tag gtitle: 'SRG-NET-000511-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000511-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
