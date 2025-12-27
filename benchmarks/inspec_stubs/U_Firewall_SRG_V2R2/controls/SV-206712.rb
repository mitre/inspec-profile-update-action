control 'SV-206712' do
  title 'The firewall must be configured to allow authorized users to record a packet capture based IP, traffic type (TCP, UDP, or ICMP), or protocol.'
  desc 'Without the ability to capture, record, and log content related to a user session, investigations into suspicious user activity would be hampered.

This configuration ensures the ability to select specific sessions to capture in order to support general auditing/incident investigation or to validate suspected misuse.'
  desc 'check', 'View the documented process for packet capture.

Verify the firewall allows authorized users to perform a packet capture based on IP, traffic type (TCP, UDP, or ICMP), or protocol.

If the firewall is not configured to allow authorized users to capture, record, and log all content related to a user session, this is a finding.'
  desc 'fix', 'Document a process for authorized users to capture, record, and log all content based on IP, traffic type (TCP, UDP, or ICMP), or protocol.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6969r297915_chk'
  tag severity: 'medium'
  tag gid: 'V-206712'
  tag rid: 'SV-206712r604133_rule'
  tag stig_id: 'SRG-NET-000399-FW-000008'
  tag gtitle: 'SRG-NET-000399'
  tag fix_id: 'F-6969r297916_fix'
  tag 'documentable'
  tag legacy: ['SV-94139', 'V-79433']
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end
