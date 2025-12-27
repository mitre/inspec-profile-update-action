control 'SV-207670' do
  title 'The ESXi host must have all security patches and updates installed.'
  desc 'Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities.'
  desc 'check', 'If vCenter Update Manager is used on the network it can be used to scan all hosts for missing patches.  From the vSphere Client go to Hosts and Clusters > Update Manager tab and select scan to view all hosts compliance status.

If vCenter Update Manager is not used a hosts compliance status must be manually determined by the build number.  The following VMware KB 1014508 can be used to correlate patches with build numbers.

If the ESXi host does not have the latest patches, this is a finding.

If the ESXi host is not on a supported release, this is a finding.

VMware also publishes Advisories on security patches, and offers a way to subscribe to email alerts for them.
https://www.vmware.com/support/policies/security_response'
  desc 'fix', 'If vCenter Update Manager is used on the network, hosts can be remediated from the vSphere Web Client. From the vSphere Web Client go to Hosts and Clusters >> Update Manager tab and select a non-compliant host and click the Remediate button.

To manually remediate a host the patch file must be copied locally and the following command run from an SSH session connected to the ESXi host, or from the ESXi shell:

esxcli software vib update -d <path to offline patch bundle.zip>'
  impact 0.7
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7925r364409_chk'
  tag severity: 'high'
  tag gid: 'V-207670'
  tag rid: 'SV-207670r388482_rule'
  tag stig_id: 'ESXI-65-000072'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7925r364410_fix'
  tag 'documentable'
  tag legacy: ['V-94479', 'SV-104309']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
