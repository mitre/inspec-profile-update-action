control 'SV-78995' do
  title 'OHS must be configured to store error log files to an appropriate storage device from which other tools can be configured to reference those log files for diagnostic/forensic purposes.'
  desc 'A web server will typically utilize logging mechanisms for maintaining a historical log of activity that occurs within a hosted application. This information can then be used for diagnostic purposes, forensics purposes, or other purposes relevant to ensuring the availability and integrity of the hosted application.

While it is important to log events identified as being critical and relevant to security, it is equally important to notify the appropriate personnel in a timely manner so they are able to respond to events as they occur. 

Manual review of the web server logs may not occur in a timely manner, and each event logged is open to interpretation by a reviewer. By integrating the web server into an overall or organization-wide log review, a larger picture of events can be viewed, and analysis can be done in a timely and reliable manner.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogDir" directive at the OHS server configuration scope.

3. If the directive is omitted, this is a finding.

4. Validate that the folder specified exists.  If the folder does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogDir" directive at the OHS server configuration scope.

3. Set the "OraLogDir" directive to an appropriate, protected location on a partition with sufficient space that is different from the partition on which the OHS software is installed; add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65257r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64505'
  tag rid: 'SV-78995r1_rule'
  tag stig_id: 'OH12-1X-000081'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-70435r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
