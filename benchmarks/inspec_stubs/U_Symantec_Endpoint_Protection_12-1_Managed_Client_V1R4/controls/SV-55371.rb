control 'SV-55371' do
  title 'The Symantec Endpoint Protection client Auto-Protect Risk Tracer must be configured to resolve source IP address.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attack mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to delete the file first will prevent the infection from spreading.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Advanced tab -> Under Additional Options -> Select Risk Tracer -> Ensure "Resolve the source computer IP address", is selected.

Criteria:  If "Resolve the source computer IP address", is not selected, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of ThreatTracerResolveIP is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Advanced tab -> Under Additional Options -> Select Risk Tracer -> Select "Resolve the source computer IP address".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42643'
  tag rid: 'SV-55371r1_rule'
  tag stig_id: 'DTASEP022'
  tag gtitle: 'DTASEP022'
  tag fix_id: 'F-48227r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
