control 'SV-240834' do
  title 'tc Server VCO must have the allowTrace parameter set to false.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.

"Trace" is a technique for a user to request internal information about tc Server. This is useful during product development, but should not be enabled in production. Allowing an attacker to conduct a Trace operation against tc Server will expose information that would be useful to perform a more targeted attack. tc Server provides the allowTrace parameter as means to disable responding to Trace requests.'
  desc 'check', 'At the command prompt, execute the following command:

grep allowTrace /etc/vco/app-server/server.xml

If "allowTrace" is set to "true", this is a finding.

Note: If no line is returned this is NOT a finding.'
  desc 'fix', %q(Navigate to and open /etc/vco/app-server/server.xml.

Navigate to and locate 'allowTrace="true"'.

Remove the 'allowTrace="true"' setting.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44067r674244_chk'
  tag severity: 'medium'
  tag gid: 'V-240834'
  tag rid: 'SV-240834r674246_rule'
  tag stig_id: 'VRAU-TC-000665'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-44026r674245_fix'
  tag 'documentable'
  tag legacy: ['SV-100749', 'V-90099']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
