control 'SV-221464' do
  title 'OHS must not contain any robots.txt files.'
  desc 'Search engines are constantly at work on the Internet.  Search engines are augmented by agents, often referred to as spiders or bots, which endeavor to capture and catalog web-site content.  In turn, these search engines make the content they obtain and catalog available to any public web user. 

To request that a well behaved search engine not crawl and catalog a server, the web server may contain a file called robots.txt for each web site hosted.  This file contains directories and files that the web server SA desires not be crawled or cataloged, but this file can also be used, by an attacker or poorly coded search engine, as a directory and file index to a site.  This information may be used to reduce an attacker’s time searching and traversing the web site to find files that might be relevant.  If information on hosted web sites needs to be protected from search engines and public view, other methods must be used.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. If the directive value specifies a directory containing a robots.txt file, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. Remove any robots.txt files from the directories specified in the "DocumentRoot" directives.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23179r415075_chk'
  tag severity: 'medium'
  tag gid: 'V-221464'
  tag rid: 'SV-221464r415077_rule'
  tag stig_id: 'OH12-1X-000227'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23168r415076_fix'
  tag 'documentable'
  tag legacy: ['SV-79181', 'V-64691']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
