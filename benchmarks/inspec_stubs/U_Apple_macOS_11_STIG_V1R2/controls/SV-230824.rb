control 'SV-230824' do
  title 'The macOS system must have the security assessment policy subsystem enabled.'
  desc 'Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Accordingly, software defined by the organization as critical must be signed with a certificate that is recognized and approved by the organization.'
  desc 'check', 'To check the status of the Security assessment policy subsystem, run the following command:

/usr/sbin/spctl --status | /usr/bin/grep enabled

If "assessments enabled" is not returned, this is a finding.'
  desc 'fix', 'To enable the Security assessment policy subsystem, run the following command:

/usr/bin/sudo /usr/sbin/spctl --master-enable'
  impact 0.7
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33769r607359_chk'
  tag severity: 'high'
  tag gid: 'V-230824'
  tag rid: 'SV-230824r599842_rule'
  tag stig_id: 'APPL-11-002064'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-33742r607360_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
