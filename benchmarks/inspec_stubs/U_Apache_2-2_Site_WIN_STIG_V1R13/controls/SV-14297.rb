control 'SV-14297' do
  title 'A private web server must utilize an approved TLS version.'
  desc 'Transport Layer Security (TLS) encryption is a required security setting for a private web server. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. A private web server must use a FIPS 140-2 approved TLS version, and all non-FIPS-approved SSL versions must be disabled.
FIPS 140-2 approved TLS versions include TLS V1.0 or greater. NIST SP 800-52 specifies the preferred configurations for government systems.
The SSLProtocol directive enables or disables SSL/TLS protocols. “SSLProtocol ALL” is a shortcut for enabling SSLv3 and TLSv1 but does not disable lower versions of SSL. Since some Apache versions enable SSL by default, SSL needs to be explicitly disabled, while also enabling TLS. To disable specific SSL Protocols, the –SSLv3 –SSLv2 switches are used with the SSLProtocol directive.'
  desc 'check', 'Verify that the ssl module is loaded. 

Open a command prompt and run the following command from the directory where httpd.exe is located: httpd –M
This will provide a list of all the loaded modules. Verify that the “ssl_module” is loaded. 

If this module is not found, this is a finding.

After determining that the ssl module is active, locate the Apache httpd.conf file. 

If unable to locate the file, perform a search of the system to find the file.

Open the httpd.conf file with an editor such as Notepad and search for the following uncommented directives: SSLProtocol and SSLEngine

For all enabled SSLProtocol directives, ensure the “-SSLv2 -SSLv3” switches to disable SSL are included in the directive.

If the SSLProtocol directive is not set to explicitly disable SSLv2 and SSLv3, this is a finding.

Note: For Apache 2.2.22 and older, all enabled SSLProtocol directives must be set to "TLSv1" or higher or this is a finding.

For all enabled SSLEngine directives, ensure they are set to “on”.

Both the SSLProtocol and SSLEngine directives must be set correctly or this is a finding.

Note: In some cases web servers are configured in an environment to support load balancing. This configuration most likely uses a content switch to control traffic to the various web servers. In this situation, the TLS certificate for the websites may be installed on the content switch versus the individual websites. This solution is acceptable as long as the web servers are isolated from the general population LAN. Users must not have the ability to bypass the content switch to access the websites.'
  desc 'fix', 'Edit the httpd.conf file and set the SSLProtocol to include “-SSLv2 -SSLv3" and the SSLEngine to “On”. For Apache 2.2.22 and older, set SSLProtocol to "TLSv1" or higher.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-35784r4_chk'
  tag severity: 'medium'
  tag gid: 'V-2262'
  tag rid: 'SV-14297r3_rule'
  tag stig_id: 'WG340 W22'
  tag gtitle: 'WG340'
  tag fix_id: 'F-31024r4_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
