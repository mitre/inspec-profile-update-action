control 'SV-71061' do
  title 'The operating system must prohibit the use of cached authenticators after one day.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', 'Verify the operating system prohibits the use of cached authenticators after one day. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prohibit the use of cached authenticators after one day.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57371r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56801'
  tag rid: 'SV-71061r1_rule'
  tag stig_id: 'SRG-OS-000383-GPOS-00166'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-61697r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
