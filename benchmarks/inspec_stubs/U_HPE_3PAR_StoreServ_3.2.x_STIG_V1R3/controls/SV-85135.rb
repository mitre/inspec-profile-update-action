control 'SV-85135' do
  title 'The storage system must allocate audit record storage capacity to store at least one weeks worth of audit records, when audit records are not immediately sent to a central audit record storage facility.'
  desc 'To verify operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', 'Verify the logging capacity is set to the maximum value of "4", with the following command:

cli% showsys -param

If the resulting list of configured parameters and values, does not contain "EventLogSize : 4M", this is a finding.'
  desc 'fix', 'Configure the audit logging capacity for the maximum storage value by entering the command:

cli% setsys EventLogSize 4M'
  impact 0.5
  ref 'DPMS Target HPE 3PAR OS 3.2.2'
  tag check_id: 'C-70913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70513'
  tag rid: 'SV-85135r1_rule'
  tag stig_id: 'HP3P-32-001700'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-76751r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
