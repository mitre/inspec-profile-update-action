control 'SV-221457' do
  title 'OHS must have all applicable patches (i.e., CPUs) applied/documented (OEM).'
  desc 'The IAVM process does not address all patches that have been identified for the host operating system or, in this case, the web server software environment. Many vendors have subscription services available to notify users of known security threats. The site needs to be aware of these fixes and make determinations based on local policy and what software features are installed, if these patches need to be applied. 

In some cases, patches also apply to middleware and database systems. Maintaining the security of web servers requires frequent reviews of security notices. Many security notices mandate the installation of a software patch to overcome security vulnerabilities. 

SAs and ISSOs should regularly check the vendor support web site for patches and information related to the web server software. All applicable security patches will be applied to the operating system and to the web server software. Security patches are deemed applicable if the product is installed, even if it is not used or is disabled.'
  desc 'check', '1. Obtain the list of patches that have been applied to OHS (e.g., $ORACLE_HOME/OPatch/opatch lsinventory).

2. In reviewing the list, also review the latest Oracle CPU at http://www.oracle.com/technetwork/topics/security/alerts-086861.html#CriticalPatchUpdates. Specifically, review the My Oracle Support note specified for Oracle Fusion Middleware to see whether there are patches available for Oracle HTTP Server 12.1.3.

3. If there are patches listed for Oracle HTTP Server 12.1.3 in the support note and they do not show in the list from Step 1 above, this is a finding.'
  desc 'fix', '1. Obtain the latest Fusion Middleware Patches applicable for Oracle HTTP Server from the My Oracle Support note associated with the latest Oracle CPU at http://www.oracle.com/technetwork/topics/security/alerts-086861.html#CriticalPatchUpdates.

2. Follow the instructions associated with each patch to successfully apply.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23172r415054_chk'
  tag severity: 'medium'
  tag gid: 'V-221457'
  tag rid: 'SV-221457r415056_rule'
  tag stig_id: 'OH12-1X-000220'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23161r415055_fix'
  tag 'documentable'
  tag legacy: ['SV-79167', 'V-64677']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
