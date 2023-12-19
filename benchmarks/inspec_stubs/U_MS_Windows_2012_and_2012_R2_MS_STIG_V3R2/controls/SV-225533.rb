control 'SV-225533' do
  title 'The Smart Card Removal Policy service must be configured to automatic.'
  desc 'The automatic start of the Smart Card Removal Policy service is required to support the smart card removal behavior requirement.'
  desc 'check', 'Verify the Smart Card Removal Policy service is configured to "Automatic". 

Run "Services.msc".

If the Startup Type for Smart Card Removal Policy is not set to Automatic, this is a finding.'
  desc 'fix', 'Configure the Startup Type for the Smart Card Removal Policy service to "Automatic".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27232r471941_chk'
  tag severity: 'medium'
  tag gid: 'V-225533'
  tag rid: 'SV-225533r569185_rule'
  tag stig_id: 'WN12-SV-000106'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27220r471942_fix'
  tag 'documentable'
  tag legacy: ['SV-52165', 'V-40206']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
