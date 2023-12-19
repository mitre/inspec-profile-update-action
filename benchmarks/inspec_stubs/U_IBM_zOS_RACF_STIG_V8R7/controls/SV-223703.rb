control 'SV-223703' do
  title 'IBM RACF must define WARN = NO on all profiles.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Review all Dataset and resource profiles in the RACF database.

If any are not defined with WARN = NO, this is a finding.'
  desc 'fix', 'Define each dataset and resource profile with WARN = NO'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25376r514797_chk'
  tag severity: 'high'
  tag gid: 'V-223703'
  tag rid: 'SV-223703r604139_rule'
  tag stig_id: 'RACF-ES-000560'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-25364r514798_fix'
  tag 'documentable'
  tag legacy: ['V-98113', 'SV-107217']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
