control 'SV-77803' do
  title 'The system must have all security patches and updates installed.'
  desc 'Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities.'
  desc 'check', 'If vCenter Update Manager is used on the network it can be used to scan all hosts for missing patches.  From the vSphere Client go to Hosts and Clusters >> Update Manager tab and select scan to view all hosts’ compliance status.

If vCenter Update Manager is not used, a host’s compliance status must be manually determined by the build number.  The following VMware KB 1014508 can be used to correlate patches with build numbers.

If the ESXi host does not have the latest patches, this is a finding.

If the ESXi host is not on a supported release, this is a finding.

VMware also publishes Advisories on security patches, and offers a way to subscribe to email alerts for them.
https://www.vmware.com/support/policies/security_response'
  desc 'fix', 'If vCenter Update Manager is used on the network, hosts can be remediated from the vSphere Client.  From the vSphere Client go to Hosts and Clusters > Update Manager tab and select a non-compliant host and click the Remediate button.

To manually remediate a host the patch file must be copied locally and the following command run:

esxcli software vib update -d <path to offline patch bundle.zip>'
  impact 0.7
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64047r1_chk'
  tag severity: 'high'
  tag gid: 'V-63313'
  tag rid: 'SV-77803r1_rule'
  tag stig_id: 'ESXI-06-000072'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69231r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
