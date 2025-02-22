control 'SV-237908' do
  title 'The IBM z/VM Journal option must be specified in the Product Configuration File.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The JOURNALING statement tells z/VM CP to include the journaling facility and to enable the system being initialized to set and query the journaling facility.'
  desc 'check', 'Examine the "Product Configuration" file.

If the JOURNALING Statement does not specify "ON", this is a finding.'
  desc 'fix', %q(Configure the Product Configuration files' JOURNALING statement to "JOURNALING ON".)
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41118r858946_chk'
  tag severity: 'medium'
  tag gid: 'V-237908'
  tag rid: 'SV-237908r858948_rule'
  tag stig_id: 'IBMZ-VM-000320'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-41077r858947_fix'
  tag 'documentable'
  tag legacy: ['SV-93569', 'V-78863']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
