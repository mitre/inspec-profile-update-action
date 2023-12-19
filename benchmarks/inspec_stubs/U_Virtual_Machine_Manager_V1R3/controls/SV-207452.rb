control 'SV-207452' do
  title 'The VMM must allocate audit record storage capacity to store at least one weeks worth of audit records when audit records are not immediately sent to a central audit record storage facility.'
  desc 'In order to ensure VMMs have a sufficient storage capacity in which to write the audit logs, VMMs need to be able to allocate audit record storage capacity. 

The task of allocating audit record storage capacity is usually performed during initial installation of the VMM and should be based upon anticipated audit record volume.

If a central audit record storage facility is available, the local storage capacity should be sufficient to hold audit records that would accumulate during anticipated interruptions in delivery of records to the facility.'
  desc 'check', "Verify the VMM allocates audit record storage capacity to store at least one week's worth of audit records when audit records are not immediately sent to a central audit record storage facility.

If it does not, this is a finding."
  desc 'fix', "Configure the VMM to allocate audit record storage capacity to store at least one week's worth of audit records when audit records are not immediately sent to a central audit record storage facility."
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7709r365760_chk'
  tag severity: 'medium'
  tag gid: 'V-207452'
  tag rid: 'SV-207452r854623_rule'
  tag stig_id: 'SRG-OS-000341-VMM-001220'
  tag gtitle: 'SRG-OS-000341'
  tag fix_id: 'F-7709r365761_fix'
  tag 'documentable'
  tag legacy: ['V-57105', 'SV-71365']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
