control 'SV-100737' do
  title 'tc Server VCAC must set URIEncoding to UTF-8.'
  desc "Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application. 

An attacker can also enter Unicode into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks.

To mitigate against many types of character-based vulnerabilities, tc Server should be configured to use a consistent character set. The URIEncoding attribute on the Connector nodes provides the means for tc Server to enforce a consistent character set encoding."
  desc 'check', 'Navigate to and open /etc/vcac/server.xml.

Navigate to the <Connector> node.

If the value of "URIEncoding" is not set to "UTF-8" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /etc/vcac/server.xml.

Navigate to the <Connector> node.

Configure the <Connector> node with the value 'URIEncoding="UTF-8"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90087'
  tag rid: 'SV-100737r1_rule'
  tag stig_id: 'VRAU-TC-000630'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag fix_id: 'F-96829r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
