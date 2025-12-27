control 'SV-78313' do
  title 'The VMM must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs and guest VMs by verifying Image Profile and VIP Acceptance Levels.'
  desc 'Verify the ESXi Image Profile to only allow signed VIBs.  An unsigned VIB represents untested code installed on an ESXi host.  The ESXi Image profile supports four acceptance levels: 

(1) VMwareCertified - VIBs created, tested and signed by VMware
(2) VMwareAccepted - VIBs created by a VMware partner but tested and signed by VMware, 
(3) PartnerSupported - VIBs created, tested and signed by a certified VMware partner 
(4) CommunitySupported - VIBs that have not been tested by VMware or a VMware partner.  

Community Supported VIBs are not supported and do not have a digital signature.  To protect the security and integrity of your ESXi hosts do not allow unsigned (CommunitySupported) VIBs to be installed on your hosts.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Security Profile.  Under "Host Image Profile Acceptance Level" view the acceptance level.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

$esxcli = Get-EsxCli
$esxcli.software.acceptance.get()

If the acceptance level is CommunitySupported, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Security Profile.  Under "Host Image Profile Acceptance Level" edit the acceptance level to be either VMwareCertified, VMwareAccepted, or PartnerSupported.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

$esxcli = Get-EsxCli
$esxcli.software.acceptance.Set("PartnerSupported")

Note: VMwareCertified or VMwareAccepted may be substituted for PartnerSupported, depending upon local requirements.'
  impact 0.7
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64573r1_chk'
  tag severity: 'high'
  tag gid: 'V-63823'
  tag rid: 'SV-78313r1_rule'
  tag stig_id: 'ESXI-06-100047'
  tag gtitle: 'SRG-OS-000370-VMM-001460'
  tag fix_id: 'F-69751r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
