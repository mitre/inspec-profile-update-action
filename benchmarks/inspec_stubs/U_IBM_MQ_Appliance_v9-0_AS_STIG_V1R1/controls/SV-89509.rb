control 'SV-89509' do
  title 'The MQ Appliance messaging server must use DoD- or CNSS-approved PKI Class 3 or Class 4 certificates.'
  desc 'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The messaging server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc 'check', 'From the MQ Appliance WebGUI, click on the Administration (gear) icon.

Click on Main >> File Management.

Click on the cert directory.

Click on the "Details" action to the right of each cert to display its attributes.

Verify that each certificate attribute meets organizationally approved requirements.

If any certificates have not been issued by a DoD- or CNSS-approved PKI CA, this is a finding.'
  desc 'fix', 'Install approved certificates that have been issued by a DoD CA.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74693r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74835'
  tag rid: 'SV-89509r1_rule'
  tag stig_id: 'MQMH-AS-000830'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag fix_id: 'F-81451r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
