control 'SV-258749' do
  title 'The ESXi host must maintain the confidentiality and integrity of information during transmission by exclusively enabling Transport Layer Security (TLS) 1.2.'
  desc 'TLS 1.0 and 1.1 are deprecated protocols with well-published shortcomings and vulnerabilities. TLS 1.2 should be enabled on all interfaces and SSLv3, TL 1.1, and 1.0 disabled, where supported.

Mandating TLS 1.2 may break third-party integrations and add-ons to vSphere. Test these integrations carefully after implementing TLS 1.2 and roll back where appropriate.

On interfaces where required functionality is broken with TLS 1.2, this finding is not applicable until such time as the third-party software supports TLS 1.2.

Modify TLS settings in the following order:
1. vCenter.
2. ESXi.

'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.ESXiVPsDisabledProtocols" value and verify it is set to "sslv3,tlsv1,tlsv1.1".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols

If the "UserVars.ESXiVPsDisabledProtocols" setting is set to a value other than "sslv3,tlsv1,tlsv1.1", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "UserVars.ESXiVPsDisabledProtocols" value and configure it to "sslv3,tlsv1,tlsv1.1".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Set-AdvancedSetting -Value "sslv3,tlsv1,tlsv1.1"'
  impact 0.7
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62489r933306_chk'
  tag severity: 'high'
  tag gid: 'V-258749'
  tag rid: 'SV-258749r933308_rule'
  tag stig_id: 'ESXI-80-000161'
  tag gtitle: 'SRG-OS-000425-VMM-001710'
  tag fix_id: 'F-62398r933307_fix'
  tag satisfies: ['SRG-OS-000425-VMM-001710', 'SRG-OS-000426-VMM-001720']
  tag 'documentable'
  tag cci: ['CCI-002420', 'CCI-002422']
  tag nist: ['SC-8 (2)', 'SC-8 (2)']
end
