control 'SV-209606' do
  title 'The macOS system must have the security assessment policy subsystem enabled.'
  desc 'Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Accordingly, software defined by the organization as critical must be signed with a certificate that is recognized and approved by the organization.'
  desc 'check', 'To check the status of the Security assessment policy subsystem, run the following command:

/usr/bin/sudo /usr/sbin/spctl --status | /usr/bin/grep enabled

If nothing is returned, this is a finding.'
  desc 'fix', 'To enable the Security assessment policy subsystem, run the following command:

/usr/bin/sudo /usr/sbin/spctl --master-enable'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9857r282300_chk'
  tag severity: 'high'
  tag gid: 'V-209606'
  tag rid: 'SV-209606r610285_rule'
  tag stig_id: 'AOSX-14-002064'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-9857r282301_fix'
  tag 'documentable'
  tag legacy: ['SV-105089', 'V-95951']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
