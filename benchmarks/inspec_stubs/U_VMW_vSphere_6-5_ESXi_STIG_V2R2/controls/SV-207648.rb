control 'SV-207648' do
  title 'The ESXi Image Profile and VIB Acceptance Levels must be verified.'
  desc 'Verify the ESXi Image Profile to only allow signed VIBs.  An unsigned VIB represents untested code installed on an ESXi host.  The ESXi Image profile supports four acceptance levels: 

(1) VMwareCertified - VIBs created, tested and signed by VMware
(2) VMwareAccepted - VIBs created by a VMware partner but tested and signed by VMware, 
(3) PartnerSupported - VIBs created, tested and signed by a certified VMware partner 
(4) CommunitySupported - VIBs that have not been tested by VMware or a VMware partner.  

Community Supported VIBs are not supported and do not have a digital signature.  To protect the security and integrity of your ESXi hosts do not allow unsigned (CommunitySupported) VIBs to be installed on your hosts.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Security Profile. Under "Host Image Profile Acceptance Level" view the acceptance level.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

$esxcli = Get-EsxCli
$esxcli.software.acceptance.get()

If the acceptance level is CommunitySupported, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Security Profile. Under "Host Image Profile Acceptance Level" click Edit… and use the pull-down selection, set the acceptance level to be VMwareCertified, VMwareAccepted, or PartnerSupported.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

$esxcli = Get-EsxCli
$esxcli.software.acceptance.Set("PartnerSupported")

Note: VMwareCertified or VMwareAccepted may be substituted for PartnerSupported, depending upon local requirements.'
  impact 0.7
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7903r364343_chk'
  tag severity: 'high'
  tag gid: 'V-207648'
  tag rid: 'SV-207648r379825_rule'
  tag stig_id: 'ESXI-65-000047'
  tag gtitle: 'SRG-OS-000366-VMM-001430'
  tag fix_id: 'F-7903r364344_fix'
  tag 'documentable'
  tag legacy: ['V-94041', 'SV-104127']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
