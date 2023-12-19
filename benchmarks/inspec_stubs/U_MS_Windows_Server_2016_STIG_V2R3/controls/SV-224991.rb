control 'SV-224991' do
  title 'Domain controllers must have a PKI server certificate.'
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
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26682r465875_chk'
  tag severity: 'medium'
  tag gid: 'V-224991'
  tag rid: 'SV-224991r569186_rule'
  tag stig_id: 'WN16-DC-000280'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-26670r465876_fix'
  tag 'documentable'
  tag legacy: ['V-73611', 'SV-88275']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
