control 'SV-48126' do
  title 'The system must be configured to ignore NetBIOS name release requests except from WINS servers.'
  desc "Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack. The DoS consists of sending a NetBIOS name release request to the server for each entry in the server's cache, causing a response delay in the normal operation of the servers WINS resolution capability."
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\Netbt\Parameters\

Value Name:  NoNameReleaseOnDemand

Value Type:  REG_DWORD
Value:  1)
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44852r2_chk'
  tag severity: 'low'
  tag gid: 'V-4116'
  tag rid: 'SV-48126r2_rule'
  tag stig_id: 'WN08-SO-000043'
  tag gtitle: 'Name-Release Attacks'
  tag fix_id: 'F-41263r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
