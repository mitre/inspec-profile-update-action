control 'SV-205645' do
  title 'Windows Server 2019 domain controllers must have a PKI server certificate.'
  desc 'Domain controllers are part of the chain of trust for PKI authentications. Without the appropriate certificate, the authenticity of the domain controller cannot be verified. Domain controllers must have a server certificate to establish authenticity as part of PKI authentications in the domain.'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Run "MMC".

Select "Add/Remove Snap-in" from the "File" menu.

Select "Certificates" in the left pane and click the "Add >" button.

Select "Computer Account" and click "Next".

Select the appropriate option for "Select the computer you want this snap-in to manage" and click "Finish".

Click "OK".

Select and expand the Certificates (Local Computer) entry in the left pane.

Select and expand the Personal entry in the left pane.

Select the Certificates entry in the left pane.

If no certificate for the domain controller exists in the right pane, this is a finding.'
  desc 'fix', 'Obtain a server certificate for the domain controller.'
  impact 0.5
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-5910r354853_chk'
  tag severity: 'medium'
  tag gid: 'V-205645'
  tag rid: 'SV-205645r569188_rule'
  tag stig_id: 'WN19-DC-000280'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-5910r354854_fix'
  tag 'documentable'
  tag legacy: ['V-93481', 'SV-103567']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
