control 'SV-78391' do
  title 'The VMM must implement cryptographic mechanisms to prevent unauthorized modification of all information at rest on all VMM components by verifying Image Profile and VIP Acceptance Levels.'
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
  tag check_id: 'C-64651r1_chk'
  tag severity: 'high'
  tag gid: 'V-63901'
  tag rid: 'SV-78391r1_rule'
  tag stig_id: 'ESXI-06-200047'
  tag gtitle: 'SRG-OS-000404-VMM-001650'
  tag fix_id: 'F-69829r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
