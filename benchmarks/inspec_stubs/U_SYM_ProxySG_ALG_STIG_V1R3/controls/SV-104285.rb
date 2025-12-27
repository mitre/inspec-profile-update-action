control 'SV-104285' do
  title 'Symantec ProxySG must tailor the Exceptions messages to generate error messages that provide the information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Providing too much information in error messages risks compromising the data and security of the application and system.

Organizations must carefully consider the structure/content of error messages. The required information within error messages will vary based on the protocol and error condition. Information that could be exploited by adversaries includes, for example, ICMP messages that reveal the use of firewalls or access control lists.

The ProxySG is designed to not reveal useful information to adversaries in error messages, although it may be configured to display custom exception pages to comply with site-specific requirements.'
  desc 'check', 'On a client workstation configured to use the ProxySG as its web gateway, browse to a prohibited website and observe the error page displayed.

If Symantec ProxySG does not tailor the Exceptions messages to generate error messages that provide the information necessary for corrective actions without revealing information that could be exploited by adversaries, this is a finding.'
  desc 'fix', 'Configure the ProxySG to tailor the Exceptions messages to generate error messages that provide only the information necessary for corrective actions.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Policy >> Exceptions.
3. Change "Install Exceptions Definitions from" to "Text Editor" and click "Install".
4. Refer to the Custom Exception Pages for ProxySG Guide for more information on creating the text for this field. 
5. After the text is entered, click Install >> Apply.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93517r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94331'
  tag rid: 'SV-104285r1_rule'
  tag stig_id: 'SYMP-AG-000590'
  tag gtitle: 'SRG-NET-000273-ALG-000129'
  tag fix_id: 'F-100447r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
