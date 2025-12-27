control 'SV-75247' do
  title 'The Google Search Appliance must employ cryptographic mechanisms preventing the unauthorized disclosure of information during transmission unless the transmitted data is otherwise protected by alternative physical measures.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism in order to protect the information during transmission.  This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPSEC tunnel. 

Alternative physical protection measures include, Protected Distribution Systems (PDS). PDS are used to transmit unencrypted classified NSI through an area of lesser classification or control. In as much as the classified NSI is unencrypted, the PDS must provide adequate electrical, electromagnetic, and physical safeguards to deter exploitation. Refer to NSTSSI No. 7003 for additional details on a PDS.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "SSL Settings".

Under "Other Settings" - If "Use HTTPS when serving both public and secure results" is checked, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "SSL Settings".

Under "Other Settings" - Select "Use HTTPS when serving both public and secure results".'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61719r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60795'
  tag rid: 'SV-75247r1_rule'
  tag stig_id: 'GSAP-00-000910'
  tag gtitle: 'SRG-APP-000264'
  tag fix_id: 'F-66477r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001131']
  tag nist: ['SC-9 (1)']
end
