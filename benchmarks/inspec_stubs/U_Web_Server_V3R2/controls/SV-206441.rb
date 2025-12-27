control 'SV-206441' do
  title 'The web server must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

An example of this would be an SMTP queue. This queue may be added to a web server through an SMTP module to enhance error reporting or to allow developers to add SMTP functionality to their applications. 

Any modules used by the web server that queue data before transmission must maintain the confidentiality and integrity of the information before the data is transmitted.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine if the web server maintains the confidentiality and integrity of information during preparation before transmission.

If the confidentiality and integrity are not maintained, this is a finding.'
  desc 'fix', 'Configure the web server to maintain the confidentiality and integrity of information during preparation for transmission.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6702r377915_chk'
  tag severity: 'medium'
  tag gid: 'V-206441'
  tag rid: 'SV-206441r879812_rule'
  tag stig_id: 'SRG-APP-000441-WSR-000181'
  tag gtitle: 'SRG-APP-000441'
  tag fix_id: 'F-6702r377916_fix'
  tag 'documentable'
  tag legacy: ['SV-70267', 'V-56013']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
