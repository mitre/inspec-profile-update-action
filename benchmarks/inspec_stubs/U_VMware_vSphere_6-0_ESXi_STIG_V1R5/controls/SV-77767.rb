control 'SV-77767' do
  title 'The system must enable bidirectional CHAP authentication for iSCSI traffic.'
  desc 'When enabled, vSphere performs bidirectional authentication of both the iSCSI target and host. There is a potential for a MiTM attack, when not authenticating both the iSCSI target and host, in which an attacker might impersonate either side of the connection to steal data. Bidirectional authentication mitigates this risk.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Storage Adapters >> Select the iSCSI adapter >> Properties >> CHAP.  View the CHAP configuration and verify CHAP is required for target and host authentication.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties

If iSCSI is not used, this is not a finding.

If iSCSI is used and CHAP is not set to required for both the target and host, this is a finding.

If iSCSI is used and unique CHAP secrets are not used for each host, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Storage Adapters >> Select the iSCSI adapter >> Properties >> CHAP.  Change CHAP and Mutual CHAP to "Use CHAP" and enter a unique secret.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Set-VMHostHba -ChapType Required -ChapName "chapname" -ChapPassword "password" -MutualChapEnabled $true -MutualChapName "mutualchapname" -MutualChapPassword "mutualpassword"'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64011r1_chk'
  tag severity: 'low'
  tag gid: 'V-63277'
  tag rid: 'SV-77767r1_rule'
  tag stig_id: 'ESXI-06-000054'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69195r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
