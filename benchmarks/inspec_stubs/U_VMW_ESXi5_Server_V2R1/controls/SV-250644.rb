control 'SV-250644' do
  title 'The Image Profile and VIB Acceptance Levels must be verified.'
  desc 'The ESXi Image profile supports four acceptance levels: 
 
(1) VMwareCertified - VIBs created, tested and signed by VMware 
(2) VMwareAccepted - VIBs created by a VMware partner but tested and signed by VMware
(3) PartnerSupported - VIBs created, tested and signed by a certified VMware partner
(4) CommunitySupported - VIBs that have not been tested by VMware or a VMware partner

Community Supported VIBs are not supported and do not have a digital signature. An unsigned VIB represents untested code installed on an ESXi host. To protect the security and integrity of an ESXi host, unsigned (CommunitySupported) VIBs must not be installed.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the host and verify the host and VIB acceptance level(s) are not set to "CommunitySupported" by running the command(s): 
# esxcli software acceptance get
# esxcli software vib list.

If the host or listed VIB acceptance levels allow "CommunitySupported", this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the host and set the host acceptance level to at least "PartnerSupported" by running the command: 
# esxcli software acceptance set --<level>

Re-enable Lockdown Mode on the host.'
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54079r798929_chk'
  tag severity: 'high'
  tag gid: 'V-250644'
  tag rid: 'SV-250644r798931_rule'
  tag stig_id: 'SRG-OS-000193-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54033r798930_fix'
  tag 'documentable'
  tag legacy: ['SV-51265', 'V-39407']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
