control 'SV-226307' do
  title 'The system must be configured to ignore NetBIOS name release requests except from WINS servers.'
  desc "Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack.  The DoS consists of sending a NetBIOS name release request to the server for each entry in the server's cache, causing a response delay in the normal operation of the servers WINS resolution capability."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters\\

Value Name:  NoNameReleaseOnDemand

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', %q(Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers" to "Enabled".   

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28009r476765_chk'
  tag severity: 'low'
  tag gid: 'V-226307'
  tag rid: 'SV-226307r569184_rule'
  tag stig_id: 'WN12-SO-000043'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-27997r476766_fix'
  tag 'documentable'
  tag legacy: ['SV-52928', 'V-4116']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
