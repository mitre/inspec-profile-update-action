control 'SV-242188' do
  title 'The SMS must be configured to remove or disable non-essential capabilities on SMS and TPS which are not required for operation or not related to IDPS functionality (e.g., web server, SSH, telnet, and TAXII).'
  desc 'An IDPS can be capable of providing a wide variety of capabilities. Not all of these capabilities are necessary. Unnecessary services, functions, and applications increase the attack surface (sum of attack vectors) of a system. These unnecessary capabilities are often overlooked and therefore may remain unsecured.'
  desc 'check', '1. In the Trend Micro SMS interface, go to the "Devices" tab". 
2. Select the Device to be modified. 
3. Click "Device Configuration" and "Services". 

If SSH is enabled, this is a finding. 

Under "FIPS Settings", if the box is unchecked, this is a finding.'
  desc 'fix', '1. In the Trend Micro SMS interface, go to the "Devices" tab". 
2. Then Select the Device to be modified. 
3. Click "Device Configuration" and "Services". 
4. Uncheck enabled for SSH. 
5. Go to "FIPS Settings", select "enabled" for "FIPS Mode". 
6. Click OK. 
CAUTION: This should be done under an approved maintenance window, as selecting FIPS Mode will cause the TPS to reboot.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45463r710105_chk'
  tag severity: 'medium'
  tag gid: 'V-242188'
  tag rid: 'SV-242188r710107_rule'
  tag stig_id: 'TIPP-IP-000230'
  tag gtitle: 'SRG-NET-000131-IDPS-00011'
  tag fix_id: 'F-45421r710106_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
