control 'SV-254338' do
  title 'Windows Server 2022 must be configured to ignore NetBIOS name release requests except from WINS servers.'
  desc "Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack. The DoS consists of sending a NetBIOS name release request to the server for each entry in the server's cache, causing a response delay in the normal operation of the server's WINS resolution capability."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters\\

Value Name:  NoNameReleaseOnDemand

Value Type:  REG_DWORD
Value:  0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers to "Enabled".

This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG package. "MSS-Legacy.admx" and "MSS-Legacy.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57823r848828_chk'
  tag severity: 'low'
  tag gid: 'V-254338'
  tag rid: 'SV-254338r848830_rule'
  tag stig_id: 'WN22-CC-000060'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-57774r848829_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
