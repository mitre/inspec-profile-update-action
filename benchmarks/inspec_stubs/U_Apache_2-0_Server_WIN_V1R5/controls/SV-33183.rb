control 'SV-33183' do
  title 'The TRACE  method must be disabled.'
  desc 'Use the Apache TraceEnable directive to disable the HTTP TRACE request method. Refer to the Apache documentation for more details http://httpd.apache.org/docs/2.2/mod/core.html#traceenable. The HTTP 1.1 protocol requires support for the TRACE request method which reflects the request back as a response and was intended for diagnostics purposes. The TRACE method is not needed and is easily subject to abuse and should be disabled.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directive: TraceEnable

For any enabled TraceEnable directives ensure they are part of the server level configuration (i.e. not nested in a <Directory> or <Location> directive). Also ensure that the TraceEnable directive is set to “Off”.

If the TraceEnable directive is not part of the server level configuration and/or is not set to “off” this is a finding. If the directive does not exist in the conf file this is a finding as the default value is "On".'
  desc 'fix', 'Disable the TraceEnable directive by setting it to "off".'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26325'
  tag rid: 'SV-33183r1_rule'
  tag stig_id: 'WA00550 W22'
  tag gtitle: 'WA00550'
  tag fix_id: 'F-29467r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'DCSP-1'
end
