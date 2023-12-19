control 'SV-225239' do
  title 'Server systems must be located in a controlled access area, accessible only to authorized personnel.'
  desc 'Inadequate physical protection can undermine all other security precautions utilized to protect the system.  This can jeopardize the confidentiality, availability, and integrity of the system.  Physical security is the first line of protection of any system.'
  desc 'check', 'Verify servers are located in controlled access areas that are accessible only to authorized personnel.  If systems are not adequately protected, this is a finding.'
  desc 'fix', 'Ensure servers are located in secure, access-controlled areas.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26938r471059_chk'
  tag severity: 'medium'
  tag gid: 'V-225239'
  tag rid: 'SV-225239r569185_rule'
  tag stig_id: 'WN12-00-000001'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-26926r471060_fix'
  tag 'documentable'
  tag legacy: ['SV-52838', 'V-1070']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
