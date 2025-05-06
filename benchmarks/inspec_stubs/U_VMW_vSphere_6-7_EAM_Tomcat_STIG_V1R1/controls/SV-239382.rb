control 'SV-239382' do
  title 'ESX Agent Manager must be configured to limit access to internal packages.'
  desc 'The "package.access" entry in the "catalina.properties" file implements access control at the package level. When properly configured, a security exception will be reported if there is an errant or malicious webapp attempt to access the listed internal classes directly or if a new class is defined under the protected packages. The ESX Agent Manager comes preconfigured with the appropriate packages defined in "package.access", and this configuration must be maintained.'
  desc 'check', 'At the command prompt, execute the following command:

# grep "package.access" -A 5 /etc/vmware-eam/catalina.properties

Expected result:

package.access=\\
sun.,\\
org.apache.catalina.,\\
org.apache.coyote.,\\
org.apache.tomcat.,\\
org.apache.jasper.

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open: 

/etc/vmware-eam/catalina.properties 

Ensure that the "package.access" line is configured as follows:

package.access=\\
sun.,\\
org.apache.catalina.,\\
org.apache.coyote.,\\
org.apache.tomcat.,\\
org.apache.jasper.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 EAM Tomcat'
  tag check_id: 'C-42615r674638_chk'
  tag severity: 'medium'
  tag gid: 'V-239382'
  tag rid: 'SV-239382r674640_rule'
  tag stig_id: 'VCEM-67-000011'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-42574r674639_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
