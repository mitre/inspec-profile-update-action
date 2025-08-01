control 'SV-203733' do
  title 'The operating system must prohibit the use of cached authenticators after one day.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', 'Verify the operating system prohibits the use of cached authenticators after one day. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prohibit the use of cached authenticators after one day.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3858r375263_chk'
  tag severity: 'medium'
  tag gid: 'V-203733'
  tag rid: 'SV-203733r851804_rule'
  tag stig_id: 'SRG-OS-000383-GPOS-00166'
  tag gtitle: 'SRG-OS-000383'
  tag fix_id: 'F-3858r375264_fix'
  tag 'documentable'
  tag legacy: ['SV-71061', 'V-56801']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
