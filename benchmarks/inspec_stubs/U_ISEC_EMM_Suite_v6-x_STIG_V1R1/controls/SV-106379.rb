control 'SV-106379' do
  title 'The ISEC7 EMM Suite, Tomcat installation, and ISEC7 Suite monitor must be configured to use the Windows Trust Store for the storage of digital certificates and keys.'
  desc 'A trust store provides requisite encryption and access control to protect digital certificates from unauthorized access.'
  desc 'check', 'Log in to the ISEC7 EMM Console.

Navigate to Administration >> Configuration >> Apache Tomcat Settings.

Verify that the type of Keystore being used is: Windows-MY 

If the type of Keystore being used is not Windows-MY, this is a finding.'
  desc 'fix', 'Log in to the ISEC7 EMM Console.

Navigate to Administration >> Configuration >> Apache Tomcat Settings.

Select the type of Keystore to be used as: 

Windows-MY'
  impact 0.5
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96103r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97265'
  tag rid: 'SV-106379r1_rule'
  tag stig_id: 'ISEC-06-002530'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-102947r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
