control 'SV-100989' do
  title 'Lighttpd must be configured to use syslog.'
  desc 'A web server will typically utilize logging mechanisms for maintaining a historical log of activity that occurs within a hosted application. This information can then be used for diagnostic purposes, forensics purposes, or other purposes relevant to ensuring the availability and integrity of the hosted application.

While it is important to log events identified as being critical and relevant to security, it is equally important to notify the appropriate personnel in a timely manner so they are able to respond to events as they occur. 

Manual review of the web server logs may not occur in a timely manner, and each event logged is open to interpretation by a reviewer. By integrating the web server into an overall or organization-wide log review, a larger picture of events can be viewed, and analysis can be done in a timely and reliable manner.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'accesslog.use-syslog' /opt/vmware/etc/lighttpd/lighttpd.conf | grep -v ^#

If the value for "accesslog.use-syslog" is not set to "enable" or is missing, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the lighttpd.conf file with the following: 

accesslog.use-syslog = "enable"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-90035r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90339'
  tag rid: 'SV-100989r1_rule'
  tag stig_id: 'VRAU-LI-000405'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-97081r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
