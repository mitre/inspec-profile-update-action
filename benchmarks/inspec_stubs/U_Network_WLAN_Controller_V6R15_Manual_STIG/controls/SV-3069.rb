control 'SV-3069' do
  title 'Management connections to a network device must be established using secure protocols with FIPS 140-2 validated cryptographic modules.'
  desc 'Administration and management connections performed across a network are inherently dangerous because anyone with a packet sniffer and access to the right LAN segment can acquire the network device account and password information.  With this intercepted information they could gain access to the router and cause denial of service attacks, intercept sensitive information, or perform other destructive actions.'
  desc 'check', 'Review the network device configuration to verify only secure protocols using FIPS 140-2 validated cryptographic modules are used for any administrative access. Some of the secure protocols used for administrative and management access are listed below. This list is not all inclusive and represents a sample selection of secure protocols. 

-SSHv2
-SCP
-HTTPS using TLS

If management connections are established using protocols without FIPS 140-2 validated cryptographic modules, this is a finding.'
  desc 'fix', 'Configure the network device to use secure protocols with FIPS 140-2 validated cryptographic modules.'
  impact 0.5
  ref 'DPMS Target WLAN Controller'
  tag check_id: 'C-3532r8_chk'
  tag severity: 'medium'
  tag gid: 'V-3069'
  tag rid: 'SV-3069r5_rule'
  tag stig_id: 'NET1638'
  tag gtitle: 'Management connections  must be secured by FIPS 140-2.'
  tag fix_id: 'F-3094r5_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
