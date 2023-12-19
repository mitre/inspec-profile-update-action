control 'SV-221572' do
  title 'The URL protocol schema javascript must be disabled.'
  desc %q(Each access to a URL is handled by the browser according to the URL's "scheme". The "scheme" of a URL is the section before the ":". The term "protocol" is often mistakenly used for a "scheme". The difference is that the scheme is how the browser handles a URL and the protocol is how the browser communicates with a service.  If a scheme or its associated protocol used by a browser is insecure or obsolete, vulnerabilities can be exploited resulting in exposed data or unrestricted access to the browser's system.   The browser must be configured to disable the use of insecure and obsolete schemas (protocols).
This policy disables the listed protocol schemes in Google Chrome, URLs using a scheme from this list will not load and cannot be navigated to. If this policy is left not set or the list is empty all schemes will be accessible in Google Chrome.)
  desc 'check', 'Universal method:
1. In the omnibox (address bar) type chrome://policy.
2. If URLBlocklist is not displayed under the Policy Name column or it is not set to javascript://* under the Policy Value column, this is a finding.

Windows method:
1. Start regedit.
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\URLBlocklist.
3. If the URLBlocklist key does not exist, or the does not contain entries 1 set to javascript://*, this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with gpedit.msc. 
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
Policy Name: Block access to a list of URLs.
- Policy State: Enabled
- Policy Value 1: javascript://*'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23287r754413_chk'
  tag severity: 'medium'
  tag gid: 'V-221572'
  tag rid: 'SV-221572r754415_rule'
  tag stig_id: 'DTBC-0021'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23276r754414_fix'
  tag 'documentable'
  tag legacy: ['SV-57595', 'V-44761']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
