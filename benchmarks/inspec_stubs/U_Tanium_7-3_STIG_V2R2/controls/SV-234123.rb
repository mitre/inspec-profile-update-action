control 'SV-234123' do
  title 'The Tanium application must limit the bandwidth used in communicating with endpoints to prevent a Denial of Service (DoS) condition at the server.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of applications to mitigate the impact of DoS attacks that have occurred or are ongoing on application availability. For each application, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', %q(Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Access the server's registry by typing: regedit <enter>.

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Verify the existence of a DWORD "DownloadBytesPerSecondLimit" with a value matching what is in the system documentation.

If the DWORD "DownloadBytesPerSecondLimit" does not exist with the correct value, this is a finding.)
  desc 'fix', %q(Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Access the server's registry by typing: regedit <enter>.

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Add or modify the DWORD "DownloadBytesPerSecondLimit" to have a value consistent with the value found in the system documentation.)
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37308r610869_chk'
  tag severity: 'medium'
  tag gid: 'V-234123'
  tag rid: 'SV-234123r612749_rule'
  tag stig_id: 'TANS-SV-000062'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-37273r610870_fix'
  tag 'documentable'
  tag legacy: ['SV-102319', 'V-92217']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
