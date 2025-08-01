control 'SV-203700' do
  title 'The operating system must allocate audit record storage capacity to store at least one weeks worth of audit records, when audit records are not immediately sent to a central audit record storage facility.'
  desc 'In order to ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', "Verify the operating system allocates audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility. If it does not, this is a finding."
  desc 'fix', "Configure the operating system to allocate audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3825r375047_chk'
  tag severity: 'medium'
  tag gid: 'V-203700'
  tag rid: 'SV-203700r379690_rule'
  tag stig_id: 'SRG-OS-000341-GPOS-00132'
  tag gtitle: 'SRG-OS-000341'
  tag fix_id: 'F-3825r375048_fix'
  tag 'documentable'
  tag legacy: ['SV-71505', 'V-57245']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
