control 'SV-214847' do
  title 'The macOS system must have the security assessment policy subsystem enabled.'
  desc 'Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Accordingly, software defined by the organization as critical must be signed with a certificate that is recognized and approved by the organization.'
  desc 'check', 'To check the status of the Security assessment policy subsystem, run the following command:

/usr/bin/sudo /usr/sbin/spctl --status | /usr/bin/grep enabled

If nothing is returned, this is a finding.'
  desc 'fix', 'To enable the Security assessment policy subsystem, run the following command:

/usr/bin/sudo /usr/sbin/spctl --master-enable'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16047r397113_chk'
  tag severity: 'high'
  tag gid: 'V-214847'
  tag rid: 'SV-214847r609363_rule'
  tag stig_id: 'AOSX-13-000430'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-16045r397114_fix'
  tag 'documentable'
  tag legacy: ['SV-96269', 'V-81555']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
