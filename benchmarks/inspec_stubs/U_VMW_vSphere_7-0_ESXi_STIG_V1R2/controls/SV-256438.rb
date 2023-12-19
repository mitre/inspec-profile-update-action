control 'SV-256438' do
  title 'The ESXi host must verify certificates for SSL syslog endpoints.'
  desc 'When sending syslog data to a remote host, ESXi can be configured to use any combination of TCP, UDP and SSL transports. When using SSL, the server certificate must be validated to ensure that the host is connecting to a valid syslog server.'
  desc 'check', 'If SSL is not used for a syslog target, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Syslog.global.logCheckSSLCerts" value and verify it is set to "true".

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logCheckSSLCerts

If the "Syslog.global.logCheckSSLCerts" setting is not set to "true", this is a finding.'
  desc 'fix', %q(To configure SSL syslog endpoint certificate checking it must be turned on and also the trusted certificate chain must be added to ESXi's trusted store.

From the vSphere Client go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Syslog.global.logCheckSSLCerts" value and set it to "true".

Copy the PEM formatted trusted CA certificate so that is accessible to the host and append the contents to /etc/vmware/ssl/castore.pem by running the follow command:

# <path/to/cacert> >> /etc/vmware/ssl/castore.pem

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logCheckSSLCerts | Set-AdvancedSetting -Value "true"

Copy the PEM formatted trusted CA certificate so that is accessible to the host.

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.security.certificatestore.add.CreateArgs()
$arguments.filename = <path/to/cacert>
$esxcli.system.security.certificatestore.add.Invoke($arguments))
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60113r886093_chk'
  tag severity: 'medium'
  tag gid: 'V-256438'
  tag rid: 'SV-256438r886095_rule'
  tag stig_id: 'ESXI-70-000086'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60056r886094_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
