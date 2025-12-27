control 'SV-255282' do
  title 'The HPE 3PAR operating system must be configured to allocate audit record storage capacity to store at least one week of audit records, even though all audit records are immediately sent to a centralized audit record storage system (SIEM).'
  desc 'To ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', 'To verify the logging capacity is set to the maximum value of "4", enter the following command:
cli%  showsys -param

In the resulting list of configured parameters and values, if the following line does not appear, this is a finding.
cli%  EventLogSize : 4M'
  desc 'fix', 'Enter the following command to configure the audit logging capacity for the maximum storage value:
cli%  setsys EventLogSize 4M'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58955r870163_chk'
  tag severity: 'medium'
  tag gid: 'V-255282'
  tag rid: 'SV-255282r870165_rule'
  tag stig_id: 'HP3P-33-001700'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-58899r870164_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
