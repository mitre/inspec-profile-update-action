control 'SV-256410' do
  title 'The ESXi Image Profile and vSphere Installation Bundle (VIB) acceptance levels must be verified.'
  desc 'Verify the ESXi Image Profile to only allow signed VIBs. An unsigned VIB represents untested code installed on an ESXi host. The ESXi Image profile supports four acceptance levels: 

1. VMwareCertified - VIBs created, tested, and signed by VMware.
2. VMwareAccepted - VIBs created by a VMware partner but tested and signed by VMware. 
3. PartnerSupported - VIBs created, tested, and signed by a certified VMware partner. 
4. CommunitySupported - VIBs that have not been tested by VMware or a VMware partner. 

Community Supported VIBs are not supported and do not have a digital signature. To protect the security and integrity of ESXi hosts, do not allow unsigned (CommunitySupported) VIBs to be installed on hosts.

'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Security Profile.

Under "Host Image Profile Acceptance Level", view the acceptance level.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.software.acceptance.get.Invoke()

If the acceptance level is "CommunitySupported", this is a finding.'
  desc 'fix', 'From the vSphere Client, select the ESXi Host and go to Configure >> System >> Security Profile.

Under "Host Image Profile Acceptance Level", click "Edit..." . 

Using the drop-down selection, set the acceptance level as "VMwareCertified", "VMwareAccepted", or "PartnerSupported". The default is "PartnerSupported".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.software.acceptance.set.CreateArgs()
$arguments.level = "PartnerSupported"
$esxcli.software.acceptance.set.Invoke($arguments)

Note: "VMwareCertified" or "VMwareAccepted" may be substituted for "PartnerSupported", depending on local requirements. These are case sensitive.'
  impact 0.7
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60085r886009_chk'
  tag severity: 'high'
  tag gid: 'V-256410'
  tag rid: 'SV-256410r886011_rule'
  tag stig_id: 'ESXI-70-000047'
  tag gtitle: 'SRG-OS-000366-VMM-001430'
  tag fix_id: 'F-60028r886010_fix'
  tag satisfies: ['SRG-OS-000366-VMM-001430', 'SRG-OS-000370-VMM-001460', 'SRG-OS-000404-VMM-001650']
  tag 'documentable'
  tag cci: ['CCI-001749', 'CCI-001774', 'CCI-002475']
  tag nist: ['CM-5 (3)', 'CM-7 (5) (b)', 'SC-28 (1)']
end
