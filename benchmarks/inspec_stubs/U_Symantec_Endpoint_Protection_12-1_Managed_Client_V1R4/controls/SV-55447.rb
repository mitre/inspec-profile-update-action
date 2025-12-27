control 'SV-55447' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan actions for handling security risks upon detection must be explicitly configured at the top, Security Risks, level and not be overridden by the Security Assessment Tool sub-level.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attack mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. If files are backed up before they are repaired, this could possibly allow the infection to stay on the system.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Select the Actions tab -> Under Actions -> Under Security Risks -> Select Security Assessment Tool -> Ensure "Override actions configured for Security Risks" is NOT selected.

Criteria:  If "Override actions configured for Security Risks" is selected, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Select the Actions tab -> Under Actions -> Under Security Risks -> Select Security Assessment Tool -> Ensure "Override actions configured for Security Risks" is NOT selected.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48991r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42719'
  tag rid: 'SV-55447r2_rule'
  tag stig_id: 'DTASEP065'
  tag gtitle: 'DTASEP065'
  tag fix_id: 'F-48305r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
