control 'SV-71505' do
  title 'The operating system must allocate audit record storage capacity to store at least one weeks worth of audit records, when audit records are not immediately sent to a central audit record storage facility.'
  desc 'In order to ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', "Verify the operating system allocates audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility. If it does not, this is a finding."
  desc 'fix', "Configure the operating system to allocate audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57855r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57245'
  tag rid: 'SV-71505r1_rule'
  tag stig_id: 'SRG-OS-000341-GPOS-00132'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-62179r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
