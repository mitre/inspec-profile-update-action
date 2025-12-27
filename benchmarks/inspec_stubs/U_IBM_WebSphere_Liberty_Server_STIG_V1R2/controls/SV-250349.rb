control 'SV-250349' do
  title 'The WebSphere Liberty Server must install security-relevant software updates within the time period directed by an authoritative source.'
  desc 'Security vulnerabilities are often addressed by testing and applying the latest security patches and fix packs. The latest fixpacks can be found at: http://www-01.ibm.com/support/docview.wss?uid=swg27009661'
  desc 'check', 'Use the "productInfo(.bat/.sh) version" command to determine the WebSphere version. Review the patch level and fix pack. 

Review the latest fixpacks at: http://www-01.ibm.com/support/docview.wss?uid=swg27009661 and determine if the system is operating at the latest patch level.

If the most recent patches/fix packs have not been applied, this is a finding.'
  desc 'fix', 'Obtain WebSphere Liberty product security and patch support at http://www-01.ibm.com/support/docview.wss?uid=swg27009661. 

Run the productInfo validate command to validate the MD5 checksum file for server installation and each feature.

If a feature is not valid, the command outputs an error and lists the manifest file for the affected feature. The following example validates the features for the current installation and outputs the results to the validate.txt file:

productInfo validate --output=/tmp/validate.txt'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53784r795098_chk'
  tag severity: 'medium'
  tag gid: 'V-250349'
  tag rid: 'SV-250349r850908_rule'
  tag stig_id: 'IBMW-LS-001170'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-53738r795099_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
