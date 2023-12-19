control 'SV-234257' do
  title 'Citrix Linux Virtual Delivery Agent must implement DoD-approved encryption.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. 

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection thereby providing a degree of confidentiality. The encryption strength of mechanism is selected based on the security categorization of the information.

'
  desc 'check', 'On the Delivery Controller, ensure the SSL encryption has been enabled for the delivery group (HdxSslEnabled:True) and the Delivery Controller uses FQDN of Linux VDA to contact target Linux VDA (DnsResolutionEnabled:True). 

Execute the following commands in a PowerShell window on the Delivery Controller:
# Asnp citrix.*
# Get-BrokerAccessPolicyRule –DesktopGroupName ‘<GROUPNAME>’ | format-list HdxSslEnabled
Where <GROUPNAME> is the target Delivery Group name.

On Linux VDA, check the following:
Check if SSL listener is up and running; run following command: 
# netstat -lptn|grep ctxhdx
to see that the ctxhdx process is listening on an SSL port (443, by default).

If, on the Delivery Controller, HdxSslEnabled is not set to "true", this is a finding. 
If, on the Delivery Controller, DnsResolutionEnabled is not set to "true", this is a finding.
If, on the Linux VDS, the ctxhdx process is not listening on an SSL port (443 by default, or other approved port), this is a finding.'
  desc 'fix', 'To enable TLS encryption on the Linux VDA, a server certificate must be installed on the Citrix Broker (DDC), each Linux VDA server and root certificates must be installed on each Linux VDA server and client per DoD guidelines.
On the Linux VDA, use the enable_vdassl.sh tool to enable (or disable) TLS encryption. The tool is located in the /opt/Citrix/VDA/sbin directory. For information about options available in the tool, run the /opt/Citrix/VDA/sbin/enable_vdassl.sh -help command.

To enable TLS 1.2 on Linux VDA OS - # /opt/Citrix/VDA/bin/ctxreg update -k "HKLM\\System\\CurrentControlSet\\Control\\Citrix\\WinStations\\ssl" -v "SSLMinVersion" -d 0x00000004
To enable GOV ciphersuites only:
# /opt/Citrix/VDA/bin/ctxreg update -k "HKLM\\System\\CurrentControlSet\\Control\\Citrix\\WinStations\\ssl" -v "SSLCipherSuite" -d 0x00000001
thes restart service
# sudo /sbin/service ctxhdx restart 
[root@ LVDA]# sudo /sbin/service ctxhdx restart'
  impact 0.7
  ref 'DPMS Target Citrix VAD 7.x LVDA'
  tag check_id: 'C-37442r612325_chk'
  tag severity: 'high'
  tag gid: 'V-234257'
  tag rid: 'SV-234257r628796_rule'
  tag stig_id: 'LVDA-VD-000030'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-37407r612326_fix'
  tag satisfies: ['SRG-APP-000014', 'SRG-APP-000015', 'SRG-APP-000039', 'SRG-APP-000219', 'SRG-APP-000439', 'SRG-APP-000440', 'SRG-APP-000441', 'SRG-APP-000442']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001184', 'CCI-001414', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'SC-23', 'AC-4', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']
end
