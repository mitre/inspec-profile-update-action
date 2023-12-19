control 'SV-257220' do
  title 'The macOS system must have the security assessment policy subsystem enabled.'
  desc 'Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Accordingly, software defined by the organization as critical must be signed with a certificate that is recognized and approved by the organization.'
  desc 'check', 'Verify the macOS system is configured with the security assessment policy subsystem enabled with the following command:

/usr/sbin/spctl --status

assessments enabled

If "assessments enabled" is not returned, this is a finding.'
  desc 'fix', 'Configure the macOS system to enable the security assessment policy subsystem by installing the "Custom Policy" configuration profile.'
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60905r905291_chk'
  tag severity: 'high'
  tag gid: 'V-257220'
  tag rid: 'SV-257220r905293_rule'
  tag stig_id: 'APPL-13-002064'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-60846r905292_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
