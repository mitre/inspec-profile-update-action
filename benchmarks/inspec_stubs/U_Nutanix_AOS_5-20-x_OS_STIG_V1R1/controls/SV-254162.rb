control 'SV-254162' do
  title 'Nutanix AOS must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Confirm Nutanix AOS generates audit records for all account creation, modification, disabling, and termination.

$ sudo grep /etc/passwd /etc/audit/audit.rules
-w /etc/passwd -p wa -k audit_account_changes

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to generate audit records for all account creations, modifications, disabling, and terminations by running the following command.

$ sudo 	salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57647r846572_chk'
  tag severity: 'medium'
  tag gid: 'V-254162'
  tag rid: 'SV-254162r846574_rule'
  tag stig_id: 'NUTX-OS-000590'
  tag gtitle: 'SRG-OS-000476-GPOS-00221'
  tag fix_id: 'F-57598r846573_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
