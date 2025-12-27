control 'SV-93451' do
  title 'The bandwidth consumption for the Tanium Server must be limited.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

In the case of application DoS attacks, care must be taken when designing the application to ensure the application makes the best use of system resources. SQL queries have the potential to consume large amounts of CPU cycles if they are not tuned for optimal performance. Web services containing complex calculations requiring large amounts of time to complete can bog down if too many requests for the service are encountered within a short period of time.

The methods employed to meet this requirement will vary depending upon the technology the application uses. However, a variety of technologies exist to limit or, in some cases, eliminate the effects of application related DoS attacks. Employing increased capacity and bandwidth combined with specialized application layer protection devices and service redundancy may reduce the susceptibility to some DoS attacks.'
  desc 'check', %q(Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Access the server's registry by typing: regedit <enter>

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Verify the existence of a DWORD "DownloadBytesPerSecondLimit".

If the DWORD "DownloadBytesPerSecondLimit" does not exist with a value equal to the value recorded in the system documentation, this is a finding.

Consult with your TAM for an appropriate value and record this in the system documentation.

If this setting is not documented, this is a finding.)
  desc 'fix', %q(Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Access the server's registry by typing: regedit <enter>

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Add or modify the DWORD "DownloadBytesPerSecondLimit" to have a value that matches the value recorded in the system documentation.)
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78321r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78745'
  tag rid: 'SV-93451r1_rule'
  tag stig_id: 'TANS-SV-000055'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-85487r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
