control 'SV-95163' do
  title 'The Bromium Enterprise Controller (BEC) must be configured to provide report generation that supports after-the-fact investigations of security incidents.'
  desc 'If the report generation capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack, or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

The report generation capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools.'
  desc 'check', 'Examine the site System Security Plan (SSP) or other documentation. Verify there is a documented procedure for when security incident reports need to be exported. 

If a procedure for providing report generation that supports after-the-fact investigations of security incidents has not been documented, this is a finding.'
  desc 'fix', 'From the management console, navigate to the "Threats" menu.

1. Select the security incident in question. View all after-the-fact information. 
2. Click "Generate Report" to create a report in Security Threat Information Exchange (STIX) or Malware Attribution Enumeration and Characterization (MAEC) format.
3. Click "Threat Information" to export security incident-related information such as file hashes and IP addresses (in ".csv" format).'
  impact 0.3
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80131r1_chk'
  tag severity: 'low'
  tag gid: 'V-80459'
  tag rid: 'SV-95163r1_rule'
  tag stig_id: 'BROM-00-000825'
  tag gtitle: 'SRG-APP-000368'
  tag fix_id: 'F-87265r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001880']
  tag nist: ['AU-7 a']
end
