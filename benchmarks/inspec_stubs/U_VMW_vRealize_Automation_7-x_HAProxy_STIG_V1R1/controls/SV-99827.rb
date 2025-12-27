control 'SV-99827' do
  title 'HAProxy must provide default error files.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used. 

Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 

This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'errorfile' /etc/haproxy/haproxy.cfg

If the return value for "errorfile" does not list error pages for the following HTTP status codes, this is a finding.

400, 403, 408, 500, 502, 503, 504)
  desc 'fix', 'Create error pages for each of the HTTP status codes below:

400, 403, 408, 500, 502, 503, 504

Navigate to and open /etc/haproxy/haproxy.cfg. Navigate to the "defaults" section.

Add the following lines:

        errorfile 400 /path/to/errorPage/for/400.http
        errorfile 403 /path/to/errorPage/for/403.http
        errorfile 408 /path/to/errorPage/for/408.http
        errorfile 500 /path/to/errorPage/for/500.http
        errorfile 502 /path/to/errorPage/for/502.http
        errorfile 503 /path/to/errorPage/for/503.http
        errorfile 504 /path/to/errorPage/for/504.http'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88869r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89177'
  tag rid: 'SV-99827r1_rule'
  tag stig_id: 'VRAU-HA-000315'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-95919r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
