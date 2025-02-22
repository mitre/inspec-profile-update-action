control 'SV-251416' do
  title 'The Ivanti MobileIron Core server must configure web management tools with FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the internet) or an internal network.'
  desc 'check', 'Verify MobileIron Core is in FIPS mode. 

ssh to command line console of the Core. Enable >> show fips. Verify FIPS mode is configured.

If FIPS mode is not configured, this is a finding.'
  desc 'fix', 'Configure Core to be in FIPS mode.

ssh to command line console of the Core. Enable >> show fips. Configure fips >> reload.'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54851r806378_chk'
  tag severity: 'high'
  tag gid: 'V-251416'
  tag rid: 'SV-251416r806403_rule'
  tag stig_id: 'IMIC-11-010000'
  tag gtitle: 'SRG-APP-000412-UEM-000283'
  tag fix_id: 'F-54804r806379_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
