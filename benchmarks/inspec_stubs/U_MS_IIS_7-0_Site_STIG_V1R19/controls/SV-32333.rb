control 'SV-32333' do
  title 'A web site must not contain a robots.txt file.'
  desc 'Search engines are constantly at work on the Internet.  Search engines are augmented by agents, often referred to as spiders or bots, which endeavor to capture and catalog web-site content.  In turn, these search engines make the content they obtain and catalog available to any public web user. 

To request that a well behaved search engine not crawl and catalog a site, the web site may contain a file called robots.txt.  This file contains directories and files that the web server SA desires not be crawled or cataloged, but this file can also be used, by an attacker or poorly coded search engine, as a directory and file index to a site.  This information may be used to reduce an attacker’s time searching and traversing the web site to find files that might be relevant.  If information on the web site needs to be protected from search engines and public view, other methods must be used.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Click the Content View tab.
4. If the robots.txt file does exist, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Under the Actions pane, click Explore.
4. Delete the robots.txt file.

NOTE: If there is information on the web site that needs protection from search engines and public view, then other methods must be used to safeguard the data.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32739r4_chk'
  tag severity: 'medium'
  tag gid: 'V-2260'
  tag rid: 'SV-32333r4_rule'
  tag stig_id: 'WG310 IIS7'
  tag gtitle: 'WG310'
  tag fix_id: 'F-29066r5_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
