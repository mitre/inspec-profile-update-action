control 'SV-51533' do
  title 'Sensitive data transmitted between interconnected organizations must be encrypted using an approved mechanism for the classification level of the data transmitted.'
  desc 'The use of encryption at the appropriate level to secure the confidentiality and integrity of sensitive information is imperative to ensure a data breach does not occur when transiting a transport network.  If the information shared between interconnecting sites is marked for anything other than public release or is need to know, then it must use encryption correlating with the classification of the data in transit.  Unclassified/FOUO will need to use a FIPS 140-2 validated cryptographic module.  Classified traffic needs to use an NSA approved encryption standard.'
  desc 'check', 'Determine whether the proper encryption standard is deployed for the classification of information being shared between interconnected organizations.  Unclassified/FOUO or any need-to-know data will need to use a FIPS 140-2 validated cryptographic module.  Classified traffic must use an NSA approved encryption standard.  If the proper encryption standard is not in use for sharing information between interconnected sites, this is a finding.'
  desc 'fix', 'Implement an approved encryption mechanism for the classification of data being shared between interconnected organizations.  Unclassified/FOUO or any need-to-know data will need to use a FIPS 140-2 validated cryptographic module.  Classified traffic must use an NSA approved encryption standard.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-46821r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39666'
  tag rid: 'SV-51533r1_rule'
  tag stig_id: 'ENTD0270'
  tag gtitle: 'ENTD0270 - Sensitive data sent between organizations not encrypted.'
  tag fix_id: 'F-44674r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECCT-1, ECCT-2, ECIC-1'
end
