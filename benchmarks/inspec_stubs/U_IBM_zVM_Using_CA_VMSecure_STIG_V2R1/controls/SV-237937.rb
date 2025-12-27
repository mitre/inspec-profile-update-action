control 'SV-237937' do
  title 'The IBM z/VM journal minidisk space allocation must be large enough for one weeks worth of audit records.'
  desc 'In order to ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', 'Examine the “MDISK” statement for journaling.

If the space allocations are not large enough for one weeks’ worth of audit records, this is a finding.'
  desc 'fix', "Monitor journal minidisks for required space allocation for one week's worth of data.

The system administrator will determine the required space allocation.

Assure space allocation is large enough for one week of audit records."
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41147r649649_chk'
  tag severity: 'medium'
  tag gid: 'V-237937'
  tag rid: 'SV-237937r649651_rule'
  tag stig_id: 'IBMZ-VM-000930'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-41106r649650_fix'
  tag 'documentable'
  tag legacy: ['SV-93627', 'V-78921']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
