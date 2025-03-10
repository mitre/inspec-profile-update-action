control 'SV-207486' do
  title 'The VMM must prohibit the use of cached authenticators after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'Verify the VMM prohibits the use of cached authenticators after one day.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to prohibit the use of cached authenticators after one day.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7743r365862_chk'
  tag severity: 'medium'
  tag gid: 'V-207486'
  tag rid: 'SV-207486r854660_rule'
  tag stig_id: 'SRG-OS-000383-VMM-001570'
  tag gtitle: 'SRG-OS-000383'
  tag fix_id: 'F-7743r365863_fix'
  tag 'documentable'
  tag legacy: ['SV-71533', 'V-57273']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
